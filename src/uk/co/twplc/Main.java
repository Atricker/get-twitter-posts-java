package uk.co.twplc;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.impl.DefaultHttpClientConnection;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestContent;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

@SuppressWarnings("deprecation")
public class Main {
	
	private static final String TWITTER_CONSUMER_KEY = "YOUR KEY";
	private static final String TWITTER_CONSUMER_SECRET_KEY = "YOUR KEY";
	private static final String TWITTER_ACCESS_TOKEN = "YOUR KEY";
	private static final String TWITTER_ACCESS_TOKEN_SECRET = "YOUR KEY";
	
	private String oauth_signature_method = "HMAC-SHA1";

	public static void main(String[] args) throws Exception {
		Main main = new Main();
		System.out.println(main.getTweets("5", "kamisevy"));
	}
	
	/**
	 * Generating oauth_nonce code, it has to be random 32bit string
	 * @return
	 */
	public String generateNonce(){
		String uuid_string = UUID.randomUUID().toString();
		uuid_string = uuid_string.replaceAll("-", "");
		return uuid_string;
	}
	
	/**
	 * Generating twitter time stamp, has to be within 5 minutes to be valid
	 * @return
	 */
	public String generateTime(){
		Calendar tempcal = Calendar.getInstance();
		long ts = tempcal.getTimeInMillis();// get current time in milliseconds
		return (new Long(ts/1000)).toString();
	}
	
	public String getTweets(String count, String username){
		JSONObject jsonresponse = new JSONObject();
		String resp = "";

		// generate authorization header
		String get_or_post = "GET";
		
		String oauth_nonce = generateNonce();

		String oauth_timestamp = generateTime();

		// the parameter string must be in alphabetical order
		String parameter_string = "count="+count+"&exclude_replies=true&oauth_consumer_key=" + TWITTER_CONSUMER_KEY + 
			"&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
			"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + TWITTER_ACCESS_TOKEN + "&oauth_version=1.0&screen_name="+username;	
		//System.out.println("parameter_string=" + parameter_string);
		
		String twitter_endpoint = "https://api.twitter.com/1.1/statuses/user_timeline.json";
		String twitter_endpoint_host = "api.twitter.com";
		String twitter_endpoint_path = "/1.1/statuses/user_timeline.json";
		String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
		
		// this time the base string is signed using twitter_consumer_secret + "&" + encode(oauth_token_secret) instead of just twitter_consumer_secret + "&"
		String oauth_signature = "";
		try {
			oauth_signature = computeSignature(signature_base_string, TWITTER_CONSUMER_SECRET_KEY + "&" + TWITTER_ACCESS_TOKEN_SECRET);  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		String authorization_header_string = "OAuth oauth_consumer_key=\"" + TWITTER_CONSUMER_KEY + "\", oauth_nonce=\"" + oauth_nonce + "\", oauth_signature=\"" + encode(oauth_signature) + 
				"\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"" + oauth_timestamp + "\", oauth_token=\"" + TWITTER_ACCESS_TOKEN + "\", oauth_version=\"1.0\"";
		System.out.println("authorization_header_string=" + authorization_header_string);


		 HttpParams params = new SyncBasicHttpParams();
		 HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		 HttpProtocolParams.setContentCharset(params, "UTF-8");
		 HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
		 HttpProtocolParams.setUseExpectContinue(params, false);

		 HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
	                // Required protocol interceptors
	                new RequestContent(),
	                new RequestTargetHost(),
	                // Recommended protocol interceptors
	                new RequestConnControl(),
	                new RequestUserAgent(),
	                new RequestExpectContinue()});

		 HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
		 HttpContext context = new BasicHttpContext(null);
		 HttpHost host = new HttpHost(twitter_endpoint_host,443);
		 DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

		 context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
		 context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

		 try {
			 try {
				 SSLContext sslcontext = SSLContext.getInstance("TLS");
				 sslcontext.init(null, null, null);
				 SSLSocketFactory ssf = sslcontext.getSocketFactory();
				 Socket socket = ssf.createSocket();
				 socket.connect(
				   new InetSocketAddress(host.getHostName(), host.getPort()), 0);
				 conn.bind(socket, params);
				 
				 // the following line adds 3 params to the request just as the parameter string did above. They must match up or the request will fail.
				 BasicHttpEntityEnclosingRequest request = new BasicHttpEntityEnclosingRequest("GET", twitter_endpoint_path + "?screen_name="+username+"&count="+count+"&exclude_replies=true");
				 request.addHeader("Authorization", authorization_header_string); // always add the Authorization header
				 httpexecutor.preProcess(request, httpproc, context);
				 HttpResponse response = httpexecutor.execute(request, conn, context);

				 if(response.getStatusLine().toString().indexOf("500") != -1){
					 jsonresponse.put("response_status", "error");
					 jsonresponse.put("message", "Twitter auth error.");
				 }else{
					 // if successful, the response should be a JSONObject of tweets
					 resp = EntityUtils.toString(response.getEntity());
					 //JSONObject jo = new JSONObject(StringEscapeUtils.escapeJava(EntityUtils.toString(response.getEntity())));
					 conn.close();
				 }   
			 }catch(HttpException he){	
				 System.out.println(he.getMessage());
			 }catch(NoSuchAlgorithmException nsae){	
				 System.out.println(nsae.getMessage());
			 }catch(KeyManagementException kme){	
				 System.out.println(kme.getMessage());
			 }finally{
				 conn.close();
			 }
		 }catch(JSONException jsone){
			 System.out.println(jsone.getMessage());
		 }catch(IOException ioe){
			 System.out.println(ioe.getMessage());
		 }
		 return resp;
	}
	
	/**
	 * Generating signature string
	 * @param baseString
	 * @param keyString
	 * @return
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */
	private static String computeSignature(String baseString, String keyString) throws GeneralSecurityException, UnsupportedEncodingException {
	    SecretKey secretKey = null;

	    byte[] keyBytes = keyString.getBytes();
	    secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");

	    Mac mac = Mac.getInstance("HmacSHA1");
	    mac.init(secretKey);

	    byte[] text = baseString.getBytes();

	    return new String(Base64.encodeBase64(mac.doFinal(text))).trim();
	}
	
	/**
	 * To encode special characters 
	 * @param value
	 * @return
	 */
	public String encode(String value) {
        String encoded = null;
        try {
            encoded = URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException ignore) {
        }
        StringBuilder buf = new StringBuilder(encoded.length());
        char focus;
        for (int i = 0; i < encoded.length(); i++) {
            focus = encoded.charAt(i);
            if (focus == '*') {
                buf.append("%2A");
            } else if (focus == '+') {
                buf.append("%20");
            } else if (focus == '%' && (i + 1) < encoded.length()
                    && encoded.charAt(i + 1) == '7' && encoded.charAt(i + 2) == 'E') {
                buf.append('~');
                i += 2;
            } else {
                buf.append(focus);
            }
        }
        return buf.toString();
    }

}
