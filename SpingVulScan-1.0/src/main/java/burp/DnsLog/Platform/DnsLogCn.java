package burp.DnsLog.Platform;

import burp.BurpExtender;
import burp.DnsLog.DnsLogInterface;
import burp.DnsLog.ParamsHelpers;
import com.github.kevinsawicki.http.HttpRequest;
import java.io.PrintWriter;

public class DnsLogCn implements DnsLogInterface {
   private BurpExtender burpExtender;
   private String dnslogDomainName;
   private String tempDomain;
   private String dnsLogCookieName;
   private String dnsLogCookieValue;

   public DnsLogCn(BurpExtender burpExtender) throws InterruptedException {
      this.burpExtender = burpExtender;
      this.dnslogDomainName = "http://www.dnslog.cn/";
      this.init();
   }

   public void init() throws InterruptedException {
      int i = 0;

      while(i < 3) {
         try {
            String url = this.dnslogDomainName + "/getdomain.php";
            String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";
            HttpRequest request = HttpRequest.get((CharSequence)url);
            request.trustAllCerts();
            request.trustAllHosts();
            request.followRedirects(false);
            request.header("User-Agent", userAgent);
            request.header("Accept", "*/*");
            request.readTimeout(3000);
            request.connectTimeout(3000);
            this.tempDomain = request.body();
            String cookie = request.header("Set-Cookie");
            String sessidKey = "PHPSESSID";
            String sessidValue = ParamsHelpers.getParam(cookie, sessidKey);
            this.dnsLogCookieName = sessidKey;
            this.dnsLogCookieValue = sessidValue;
            break;
         } catch (RuntimeException var8) {
            this.burpExtender.stdout.println("尝试第" + i + "次请求DnsLogCn平台，失败！");
            Thread.sleep(3000L);
            var8.printStackTrace();
            ++i;
         }
      }

   }

   public String getTempDomain() {
      return this.tempDomain;
   }

   public String getBodyContent() throws InterruptedException {
      int i = 0;

      while(i < 3) {
         try {
            String url = this.dnslogDomainName + "/getrecords.php";
            String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";
            HttpRequest request = HttpRequest.get((CharSequence)url);
            request.trustAllCerts();
            request.trustAllHosts();
            request.followRedirects(false);
            request.header("User-Agent", userAgent);
            request.header("Accept", "*/*");
            request.header("Cookie", this.dnsLogCookieName + "=" + this.dnsLogCookieValue + ";");
            request.readTimeout(30000);
            request.connectTimeout(30000);
            String body = request.body();
            if (body.equals("[]")) {
               return null;
            }

            return body;
         } catch (Exception var6) {
            this.burpExtender.stdout.println("尝试第" + i + "次请求DnsLogCn平台，失败！");
            Thread.sleep(3000L);
            var6.printStackTrace();
            ++i;
         }
      }

      return null;
   }

   public boolean checkResult() throws InterruptedException {
      return this.getBodyContent() != null;
   }

   public String outExport() {
      String exp1 = String.format("dnsLog域名: %s", this.dnslogDomainName);
      String exp2 = String.format("dnsLog保存记录的api接口: %s", this.dnslogDomainName + "/getrecords.php");
      String exp3 = String.format("cookie: %s=%s", this.dnsLogCookieName, this.dnsLogCookieValue);
      String exp4 = String.format("dnsLog临时域名: %s", this.getTempDomain());
      return exp1 + "\n" + exp2 + "\n" + exp3 + "\n" + exp4;
   }

   public void export() {
      PrintWriter stdout = new PrintWriter(this.burpExtender.callbacks.getStdout(), true);
      stdout.println("");
      stdout.println("===========dnsLog扩展详情===========");
      stdout.println(String.format("dnsLog域名: %s", this.dnslogDomainName));
      stdout.println(String.format("dnsLog保存记录的api接口: %s", this.dnslogDomainName + "/getrecords.php"));
      stdout.println(String.format("cookie: %s=%s", this.dnsLogCookieName, this.dnsLogCookieValue));
      stdout.println(String.format("dnsLog临时域名: %s", this.getTempDomain()));
      stdout.println("===================================");
      stdout.println("");
   }
}
