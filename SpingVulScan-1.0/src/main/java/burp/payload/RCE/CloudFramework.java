package burp.payload.RCE;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.SpringIssue;
import burp.DnsLog.DnsLogInterface;
import burp.auxiliary.CheckIsSpring;
import burp.auxiliary.YamlReader;
import burp.payload.Payload;
import java.io.FileNotFoundException;
import java.util.List;

public class CloudFramework implements Payload {
   private BurpExtender burpExtender;
   private IExtensionHelpers helpers;
   private CheckIsSpring checkIsSpring;
   private YamlReader yamlReader;
   private DnsLogInterface dnsLogPlatform;
   private IHttpRequestResponse updataHttp;

   public CloudFramework(BurpExtender burpExtender, IExtensionHelpers helpers, CheckIsSpring checkIsSpring) throws FileNotFoundException {
      this.burpExtender = burpExtender;
      this.helpers = helpers;
      this.checkIsSpring = checkIsSpring;
      this.burpExtender.stdout.println("===========================正在测试是否存在：Spring Cloud Framework 远程代码执行漏洞（CVE-2022-22965）===========================");
      this.yamlReader = new YamlReader(this.burpExtender);
   }

   public IScanIssue doCheckVul(IHttpRequestResponse iHttpRequestResponse, DnsLogInterface dnsLogPlatform) {
      this.dnsLogPlatform = dnsLogPlatform;
      boolean isReverse = this.burpExtender.tags.getSettingUi().isReverseCheck();
      boolean isError = this.burpExtender.tags.getSettingUi().isErrorCheck();
      List payloads = (List)this.yamlReader.getValueByKey("CloudFramework.payloads");
      String payload1 = payloads.get(0).toString();
      String payload2 = payloads.get(1).toString();
      IScanIssue iScanIssue = null;
      if (isError) {
         iScanIssue = this.errorCheck(iHttpRequestResponse, payload1, false, "");
         if (iScanIssue == null) {
            iScanIssue = this.errorCheck(iHttpRequestResponse, payload1, true, "");
         }
      }

      if (isReverse) {
         IScanIssue scanIssue = null;

         try {
            scanIssue = this.reverseCheck(iHttpRequestResponse, payload2, false, "");
            if (scanIssue == null) {
               scanIssue = this.reverseCheck(iHttpRequestResponse, payload2, true, "");
            }
         } catch (InterruptedException var11) {
            var11.printStackTrace();
         }

         if (scanIssue != null) {
            return scanIssue;
         }
      }

      return iScanIssue;
   }

   private IScanIssue errorCheck(IHttpRequestResponse iHttpRequestResponse, String payload, boolean reqMethod, String flag) {
      IRequestInfo requestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
      List<String> headers = requestInfo.getHeaders();
      if (((String)headers.get(0)).contains("HTTP/1.1")) {
         headers.set(0, "GET /" + flag + " HTTP/1.1");
      } else {
         headers.set(0, "GET /" + flag + " HTTP/2");
      }

      byte[] newHeaderRequest = this.helpers.buildHttpMessage(headers, (byte[])null);
      String method = requestInfo.getMethod();
      String key = payload.split("=")[0];
      String value1 = String.format(payload.split("=")[1], this.checkIsSpring.randomStr(3));
      String value2 = String.format(payload.split("=")[1], "false");
      IParameter newParam = this.helpers.buildParameter(key, value1, (byte)("GET".equalsIgnoreCase(method) ? 0 : 1));
      byte[] newParamReq = this.helpers.addParameter(newHeaderRequest, newParam);
      if (reqMethod) {
         newParamReq = this.helpers.toggleRequestMethod(newParamReq);
      }

      IHttpRequestResponse requestResponse1 = this.burpExtender.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), newParamReq);
      IResponseInfo response1 = this.helpers.analyzeResponse(requestResponse1.getResponse());
      IResponseInfo request = this.helpers.analyzeResponse(requestResponse1.getRequest());
      this.burpExtender.stdout.println("[*] 正在检测：" + (String)request.getHeaders().get(0) + "\n状态码：" + response1.getStatusCode());
      if (response1.getStatusCode() == 400 || response1.getStatusCode() == 500 || response1.getStatusCode() == 502 || response1.getStatusCode() == 503) {
         newParam = this.helpers.buildParameter(key, value2, (byte)("GET".equalsIgnoreCase(method) ? 0 : 1));
         newParamReq = this.helpers.addParameter(newHeaderRequest, newParam);
         IHttpRequestResponse requestResponse2 = this.burpExtender.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), newParamReq);
         IResponseInfo response2 = this.helpers.analyzeResponse(requestResponse2.getResponse());
         this.burpExtender.stdout.println("[*] 正在检测：" + (String)response2.getHeaders().get(0) + "\n状态码：" + response1.getStatusCode());
         if (response2.getStatusCode() != 400 && response2.getStatusCode() != 500 && response2.getStatusCode() != 502 && response2.getStatusCode() != 503) {
            this.burpExtender.stdout.println("[*] 大概率存在漏洞......");
            this.updataHttp = requestResponse2;
            return new SpringIssue(requestInfo.getUrl(), "Spring Cloud Framework RCE (CVE-2022-22965)", 0, "Medium", "UnCertain", (String)null, (String)null, newParam.getName() + "=" + newParam.getValue(), (String)null, new IHttpRequestResponse[]{requestResponse2}, requestResponse2.getHttpService());
         }
      }

      return null;
   }

   private IScanIssue reverseCheck(IHttpRequestResponse iHttpRequestResponse, String payload, boolean reqMethod, String flag) throws InterruptedException {
      IRequestInfo requestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
      String method = requestInfo.getMethod();
      List<String> headers = requestInfo.getHeaders();
      if (((String)headers.get(0)).contains("HTTP/1.1")) {
         headers.set(0, "GET /" + flag + " HTTP/1.1");
      } else {
         headers.set(0, "GET /" + flag + " HTTP/2");
      }

      byte[] newHeaderRequest = this.helpers.buildHttpMessage(headers, (byte[])null);
      String dnsName = this.dnsLogPlatform.getTempDomain();
      String[] payload1 = payload.split("&");
      String key1 = payload1[0].split("=")[0];
      String value1 = String.format(payload1[0].split("=")[1], "http://" + this.checkIsSpring.randomStr(3) + dnsName);
      String key2 = String.format(payload1[1].split("=")[0], this.checkIsSpring.randomStr(3));
      String value2 = String.format(payload1[1].split("=")[1], this.checkIsSpring.randomStr(3));
      this.burpExtender.stdout.println("[*] 正在检测payload：" + payload + "\n临时域名：" + dnsName);
      IParameter param1 = this.helpers.buildParameter(key1, value1, (byte)("GET".equalsIgnoreCase(method) ? 0 : 1));
      IParameter param2 = this.helpers.buildParameter(key2, value2, (byte)("GET".equalsIgnoreCase(method) ? 0 : 1));
      byte[] newParamsReq = this.helpers.addParameter(newHeaderRequest, param1);
      newParamsReq = this.helpers.addParameter(newParamsReq, param2);
      if (reqMethod) {
         newParamsReq = this.helpers.toggleRequestMethod(newParamsReq);
      }

      IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), newParamsReq);
      if (requestResponse.getResponse() != null) {
         IRequestInfo requestInfo1 = this.helpers.analyzeRequest(requestResponse);
         this.burpExtender.stdout.println("[*] 正在校验: " + requestInfo1.getUrl() + " ...");

         for(int i = 0; i < 3; ++i) {
            if (this.dnsLogPlatform.checkResult()) {
               this.burpExtender.stdout.println("===========================检测完毕！存在：Spring Cloud Framework 远程代码执行漏洞（CVE-2022-22965）===========================");
               this.updataHttp = requestResponse;
               return new SpringIssue(requestInfo.getUrl(), "Spring Cloud Framework RCE (CVE-2022-22965)", 0, "High", "Certain", (String)null, (String)null, key1 + "=" + value1 + "&" + key2 + "=" + value2, (String)null, new IHttpRequestResponse[]{requestResponse}, requestResponse.getHttpService());
            }

            try {
               Thread.sleep(10000L);
            } catch (InterruptedException var22) {
               this.burpExtender.stderr.println(var22.getMessage());
            }
         }
      }

      this.burpExtender.stdout.println("===========================检测完毕！不存在：Spring Cloud Framework 远程代码执行漏洞（CVE-2022-22965）===========================");
      return null;
   }

   public IHttpRequestResponse export() {
      return this.updataHttp;
   }
}
