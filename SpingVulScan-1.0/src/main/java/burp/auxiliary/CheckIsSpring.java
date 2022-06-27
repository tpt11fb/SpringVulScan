package burp.auxiliary;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

public class CheckIsSpring {
   private BurpExtender burpExtender;
   private IExtensionHelpers helpers;
   public static Random random = new Random();

   public CheckIsSpring(BurpExtender burpExtender, IExtensionHelpers helpers) {
      this.burpExtender = burpExtender;
      this.helpers = helpers;
   }

   public boolean isSpring(IHttpRequestResponse httpRequestResponse, String flag, boolean isVersion2x) {
      try {
         IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
         IHttpService service = httpRequestResponse.getHttpService();
         String url = requestInfo.getUrl().toString() + flag;
         if (isVersion2x) {
            url = this.getUri(url) + "actuator/" + flag + this.randomStr(5);
         }

         byte[] newRequest = this.helpers.buildHttpRequest(new URL(service.getProtocol(), service.getHost(), service.getPort(), url));
         requestInfo = this.helpers.analyzeRequest(service, newRequest);
         List<String> headers = requestInfo.getHeaders();
         Iterator var9 = headers.iterator();

         while(var9.hasNext()) {
            String header = (String)var9.next();
            if (header.startsWith("Accept")) {
               headers.remove(header);
               headers.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
               break;
            }
         }

         IRequestInfo requestInfo1 = this.helpers.analyzeRequest(service, newRequest);
         newRequest = (new String(newRequest)).substring(requestInfo1.getBodyOffset()).getBytes();
         newRequest = this.helpers.buildHttpMessage(headers, newRequest);
         IHttpRequestResponse requestResponse = this.burpExtender.callbacks.makeHttpRequest(httpRequestResponse.getHttpService(), newRequest);
         String body = (new String(requestResponse.getResponse())).substring(this.helpers.analyzeResponse(requestResponse.getResponse()).getBodyOffset()).toLowerCase();
         if (body.contains("whitelabel error page") || body.contains("unauthorized")) {
            this.burpExtender.stdout.println("[*] 存在Spring框架: " + url);
            return true;
         }
      } catch (MalformedURLException var12) {
         var12.printStackTrace();
         this.burpExtender.stderr.println(var12.getMessage());
      }

      return false;
   }

   public String getUri(String url) {
      url = url.replace("https://", "").replace("http://", "");
      String pureUrl = url.substring(0, url.contains("?") ? url.indexOf("?") : url.length());
      pureUrl = pureUrl.substring(pureUrl.contains("/") ? pureUrl.indexOf("/") : pureUrl.length(), pureUrl.contains("/") ? pureUrl.lastIndexOf("/") : pureUrl.length());
      return pureUrl + "/";
   }

   public String randomStr(int n) {
      StringBuilder s = new StringBuilder();
      char[] stringArray = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

      for(int i = 0; i < n; ++i) {
         char num = stringArray[random.nextInt(stringArray.length)];
         s.append(num);
      }

      return s.toString();
   }
}
