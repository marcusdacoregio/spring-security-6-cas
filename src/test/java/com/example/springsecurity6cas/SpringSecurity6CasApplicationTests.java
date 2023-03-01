package com.example.springsecurity6cas;

import com.codeborne.selenide.Configuration;
import com.codeborne.selenide.Selenide;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static com.codeborne.selenide.Selenide.$;
import static com.codeborne.selenide.Selenide.open;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class SpringSecurity6CasApplicationTests {

	@LocalServerPort
	int port;

	@Container
	static final GenericContainer<?> casServer = new GenericContainer<>(DockerImageName.parse("apereo/cas:6.6.6"))
			.withCommand("--cas.standalone.configuration-directory=/etc/cas/config",
					"--server.ssl.enabled=false",
					"--server.port=8080",
					"--cas.service-registry.core.init-from-json=true",
					"--cas.service-registry.json.location=file:/etc/cas/services")
			.withExposedPorts(8080)
			.withClasspathResourceMapping("cas/services/https-1.json", "/etc/cas/services/https-1.json", BindMode.READ_WRITE)
			.waitingFor(Wait.forLogMessage(".*Ready to process requests.*", 1));

	@DynamicPropertySource
	static void casProperties(DynamicPropertyRegistry registry) {
		String casUrl = String.format("http://%s:%s/cas", casServer.getHost(), casServer.getMappedPort(8080));
		registry.add("cas.base.url", () -> casUrl);
		registry.add("cas.login.url", () -> casUrl + "/login");
		registry.add("cas.logout.url", () -> casUrl + "/logout");
	}

	@BeforeAll
	static void setUp() {
		Configuration.headless = true;
	}

	@AfterEach
	void setup() {
		Selenide.closeWindow();
	}

	@Test
	void login() {
		doLogin();
		String lead = $(By.className("lead")).text();
		assertThat(lead).isEqualTo("You are successfully logged in as casuser");
	}

	private void doLogin() {
		open("http://localhost:" + this.port);
		$(By.name("username")).setValue("casuser");
		$(By.name("password")).setValue("Mellon");
		$(By.name("submitBtn")).click();
	}

	@Test
	void loginAndLogout() {
		doLogin();
		$(By.id("rp_logout_button")).click();
		String logoutMsg = $(By.id("logout-msg")).text();
		assertThat(logoutMsg).isEqualTo("You are successfully logged out of the app, but not CAS");
	}

}
