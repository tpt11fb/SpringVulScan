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
import java.net.URL;
import java.util.Arrays;
import java.util.List;

public class SecurityOAuth2RCE implements Payload {
   private BurpExtender burpExtender;
   private IExtensionHelpers helpers;
   private CheckIsSpring checkIsSpring;
   private YamlReader yamlReader;
   private IHttpRequestResponse updataHttp;

   public SecurityOAuth2RCE(BurpExtender burpExtender, IExtensionHelpers helpers, CheckIsSpring checkIsSpring) throws FileNotFoundException {
      this.burpExtender = burpExtender;
      this.burpExtender.stdout.println("===========================正在测试是否存在：Spring Security OAuth2 远程命令执行漏洞（CVE-2016-4977）===========================");
      this.helpers = helpers;
      this.checkIsSpring = checkIsSpring;
      this.yamlReader = new YamlReader(this.burpExtender);
   }

   public IScanIssue doCheckVul(IHttpRequestResponse httpRequestResponse, DnsLogInterface dnsLogPlatform) {
      URL url = this.helpers.analyzeRequest(httpRequestResponse).getUrl();
      List payloads = (List)this.yamlReader.getValueByKey("SecurityOAuth2RCE.payloads");
      String[] usernames = ((String)payloads.get(0)).substring(9).split(",");
      String[] passwords = ((String)payloads.get(1)).substring(9).split(",");
      String payload = (String)payloads.get(2);
      this.burpExtender.stdout.println("用户名：" + Arrays.toString(usernames) + "\n密码：" + Arrays.toString(passwords) + "\npayload：" + payload);
      String[] var8 = usernames;
      int var9 = usernames.length;

      for(int var10 = 0; var10 < var9; ++var10) {
         String username = var8[var10];
         String[] var12 = passwords;
         int var13 = passwords.length;

         for(int var14 = 0; var14 < var13; ++var14) {
            String password = var12[var14];
            String up = this.helpers.base64Encode(username + ":" + password);
            IHttpRequestResponse requestResponse = this.makeRequest(httpRequestResponse, payload, up);
            IResponseInfo responseInfo1 = this.helpers.analyzeResponse(requestResponse.getResponse());
            this.burpExtender.stdout.println("响应状态码：" + responseInfo1.getStatusCode());
            String body = (new String(requestResponse.getResponse())).substring(this.helpers.analyzeResponse(requestResponse.getResponse()).getBodyOffset()).toLowerCase();
            if (body.contains("response types: [4]")) {
               this.updataHttp = requestResponse;
               this.burpExtender.stdout.println("===========================检测完毕！存在：Spring Security OAuth2 远程命令执行漏洞（CVE-2016-4977）漏洞 ===========================\n");
               return new SpringIssue(url, "Spring Security OAuth2 RCE", 0, "High", "Certain", (String)null, (String)null, "There is a vulnerability, but you need other tools to take advantage of it!", (String)null, new IHttpRequestResponse[]{requestResponse}, requestResponse.getHttpService());
            }

            if (responseInfo1.getStatusCode() == 401) {
               this.burpExtender.stdout.println("===========================检测完毕！可能存在：Spring Security OAuth2 远程命令执行漏洞（CVE-2016-4977）漏洞 ===========================\n");
               this.updataHttp = requestResponse;
               return new SpringIssue(url, "Spring Security OAuth2 RCE", 0, "Medium", "Certain", (String)null, (String)null, "There may be a vulnerability because the same authentication failed", (String)null, new IHttpRequestResponse[]{requestResponse}, requestResponse.getHttpService());
            }
         }
      }

      this.burpExtender.stdout.println("===========================检测完毕！不存在：Spring Security OAuth2 远程命令执行漏洞（CVE-2016-4977）漏洞 ===========================\n");
      return null;
   }

   private IHttpRequestResponse makeRequest(IHttpRequestResponse httpRequestResponse, String payload, String up) {
      IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
      List<String> headers = requestInfo.getHeaders();
      if (((String)headers.get(0)).contains("HTTP/1.1")) {
         headers.set(0, "GET " + payload + " HTTP/1.1");
      } else {
         headers.set(0, "GET " + payload + " HTTP/2");
      }

      headers.add("Authorization: Basic " + up);
      IHttpService service = httpRequestResponse.getHttpService();
      byte[] newRequest = this.helpers.buildHttpMessage(headers, this.helpers.stringToBytes(payload));
      return this.burpExtender.callbacks.makeHttpRequest(service, newRequest);
   }

   public IHttpRequestResponse export() {
      return this.updataHttp;
   }
}
