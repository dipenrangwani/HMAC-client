package com.hmac.config;

import java.io.UnsupportedEncodingException;

import java.net.URLEncoder;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

@SuppressWarnings({ "rawtypes", "unchecked" })
public class HMACClient {
	private static final String UTF8_CHARSET = "UTF-8";
	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private static final String REQUEST_URI = "/movie/ssd";
	private static final String REQUEST_METHOD = "GET";
	private static final String QUERY_PARAMS = "name=ferret&color=purple";

	private String secretKey = "abc11234";

	private SecretKeySpec secretKeySpec = null;
	private Mac mac = null;

	public void SignedRequestsHelper()
			throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
		byte[] secretyKeyBytes;

		secretyKeyBytes = secretKey.getBytes(UTF8_CHARSET);

		secretKeySpec = new SecretKeySpec(secretyKeyBytes, HMAC_ALGORITHM);
		mac = Mac.getInstance(HMAC_ALGORITHM);
		mac.init(secretKeySpec);
	}

	public String sign() throws NoSuchAlgorithmException {

		// sorting request-params by key
		SortedMap data = new TreeMap<>();
		String params[] = QUERY_PARAMS.split("&");
		for (String param : params) {
			String keyValue[] = param.split("=");
			data.put(keyValue[0], keyValue[1]);
		}

		// time when request is fired, maintain the common timezone for time
		// calculations between client & server.
		DateTime time = new DateTime(new DateTime(), DateTimeZone.UTC);

		// sorting data required to generate signature by key, note same order should
		// also be maintain server side to get same signature.
		SortedMap paramMap = new TreeMap<>();
		paramMap.put("method", REQUEST_METHOD);
		paramMap.put("uri", REQUEST_URI);
		paramMap.put("timestamp", time.toString());
		paramMap.put("data", data.toString());

		String toSign = canonicalize(paramMap);

		// signing data and generating hmac signature
		String hmac = hmac(toSign);

		// eliminating special characters from signature
		String sig = percentEncodeRfc3986(hmac);

		return sig;
	}

	private String hmac(String stringToSign) {
		String signature = null;
		byte[] data;
		byte[] rawHmac;
		try {
			data = stringToSign.getBytes(UTF8_CHARSET);
			rawHmac = mac.doFinal(data);
			Base64 encoder = new Base64();
			signature = new String(encoder.encode(rawHmac));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(UTF8_CHARSET + " is unsupported!", e);
		}
		return signature;
	}

	private String canonicalize(SortedMap<String, String> sortedParamMap) {
		if (sortedParamMap.isEmpty()) {
			return "";
		}

		StringBuffer buffer = new StringBuffer();
		Iterator<Map.Entry<String, String>> iter = sortedParamMap.entrySet().iterator();

		while (iter.hasNext()) {
			Map.Entry<String, String> kvpair = iter.next();
			// buffer.append(percentEncodeRfc3986(kvpair.getKey()));
			// buffer.append("=");
			buffer.append(percentEncodeRfc3986(kvpair.getValue()));
			if (iter.hasNext()) {
				buffer.append("\n");
			}
		}
		String canonical = buffer.toString();
		return canonical;
	}

	/*
	 * Removes special characters from input string
	 */
	private String percentEncodeRfc3986(String s) {
		String out;
		try {
			out = URLEncoder.encode(s, UTF8_CHARSET).replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
		} catch (UnsupportedEncodingException e) {
			out = s;
		}
		return out;
	}

	public static void main(String args[])
			throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {

		HMACClient client = new HMACClient();
		client.SignedRequestsHelper();
		String signature = client.sign();
		System.out.println(signature);

	}
}