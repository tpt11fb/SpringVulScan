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
import burp.auxiliary.ReadFile;
import burp.auxiliary.YamlReader;
import burp.payload.Payload;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class APIunauthorized implements Payload {
   private BurpExtender burpExtender;
   private IExtensionHelpers helpers;
   private CheckIsSpring checkIsSpring;
   private YamlReader yamlReader;
   private IHttpRequestResponse updataHttp;

   public APIunauthorized(BurpExtender burpExtender, IExtensionHelpers helpers, CheckIsSpring checkIsSpring) throws FileNotFoundException {
      this.burpExtender = burpExtender;
      this.helpers = helpers;
      this.burpExtender.stdout.println("===========================正在测试是否存在：API未授权，泄露===========================");
      this.helpers = helpers;
      this.checkIsSpring = checkIsSpring;
      this.yamlReader = new YamlReader(this.burpExtender);
   }

   public IScanIssue doCheckVul(IHttpRequestResponse httpRequestResponse, DnsLogInterface dnsLogPlatform) {
      int lastIndex = this.burpExtender.callbacks.getExtensionFilename().lastIndexOf(File.separator);
      String path = this.burpExtender.callbacks.getExtensionFilename().substring(0, lastIndex) + File.separator;
      ReadFile readFile = new ReadFile(path + "\\config\\apiRoute.txt");

      try {
         Set<String> routes = readFile.bigFile();
         return this.routeBoom(httpRequestResponse, routes, "");
      } catch (IOException var7) {
         var7.printStackTrace();
         return null;
      }
   }

   public IScanIssue routeBoom(IHttpRequestResponse httpRequestResponse, Set<String> routes, String flag) {
      IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
      List<String> headers = requestInfo.getHeaders();
      Iterator var6 = routes.iterator();

      IHttpRequestResponse requestResponse;
      IResponseInfo responseInfo;
      URL url;
      do {
         if (!var6.hasNext()) {
            this.burpExtender.stdout.println("===========================爆破完毕！不存在：API 未授权 ===========================\n");
            return null;
         }

         String route = (String)var6.next();
         if (((String)headers.get(0)).contains("HTTP/1.1")) {
            headers.set(0, "GET " + flag + route + " HTTP/1.1");
         } else {
            headers.set(0, "GET " + flag + route + " HTTP/2");
         }

         IHttpService service = httpRequestResponse.getHttpService();
         byte[] newRequest = this.helpers.buildHttpMessage(headers, (byte[])null);
         requestResponse = this.burpExtender.callbacks.makeHttpRequest(service, newRequest);
         responseInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
         url = this.helpers.analyzeRequest(requestResponse).getUrl();
      } while(responseInfo.getStatusCode() != 200 && responseInfo.getStatusCode() != 302 && responseInfo.getStatusCode() != 500 && responseInfo.getStatusCode() != 401);

      if (!responseInfo.getInferredMimeType().equals("")) {
         this.burpExtender.stdout.println("===========================检测完毕！存在：API 未授权 ===========================\n");
         this.updataHttp = requestResponse;
         return new SpringIssue(url, "APIunauthorized", 0, "Medium", "Tentative", (String)null, (String)null, "API exists, API leakage is probable, please check manually", (String)null, new IHttpRequestResponse[]{requestResponse}, requestResponse.getHttpService());
      } else {
         this.burpExtender.stdout.println("===========================检测完毕！可能存在：API 未授权 ===========================\n");
         this.updataHttp = requestResponse;
         return new SpringIssue(url, "API unauthorized", 0, "Low", "Tentative", (String)null, (String)null, "It is detected that the API burst is echoed, and there may be a route, which needs to be verified by manual test", (String)null, new IHttpRequestResponse[]{requestResponse}, requestResponse.getHttpService());
      }
   }

   public IHttpRequestResponse export() {
      return this.updataHttp;
   }
}
