package com.example.springsecurity6cas;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class SpringSecurity6CasApplication {

	public static void main(String[] args) {
		disableSslVerification();
		SpringApplication.run(SpringSecurity6CasApplication.class, args);
	}

	@Controller
	class IndexController {

		@GetMapping("/")
		@ResponseBody
		public String index() {
			return "index";
		}

		@GetMapping("/logout-success")
		public String logoutSuccess() {
			return "redirect:/logout/cas";
		}

	}

	/**
	 * disable SSL
	 */
	private static void disableSslVerification() {
		try {
			// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[]{
					new X509TrustManager() {
						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return null;
						}

						public void checkClientTrusted(X509Certificate[] certs,
													   String authType) {
						}

						public void checkServerTrusted(X509Certificate[] certs,
													   String authType) {
						}
					}};

			// Install the all-trusting trust manager
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

			// Create all-trusting host name verifier
			HostnameVerifier allHostsValid = new HostnameVerifier() {
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			};

			// Install the all-trusting host verifier
			HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		}
	}
}
