package burp.Scan;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.auxiliary.CheckIsSpring;
import burp.payload.ScanPayload;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Scanner implements IScannerCheck {
   private BurpExtender burpExtender;
   private IExtensionHelpers helpers;
   private String vulName;
   private CheckIsSpring checkIsSpring;
   private final Set<String> Scan = new HashSet();

   public Scanner(BurpExtender burpExtender) {
      this.burpExtender = burpExtender;
      this.helpers = this.burpExtender.helpers;
      this.checkIsSpring = new CheckIsSpring(this.burpExtender, this.helpers);
   }

   public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
      if (!this.burpExtender.tags.getSettingUi().isEnable()) {
         return null;
      } else {
         try {
            boolean filterSpring = this.burpExtender.tags.getSettingUi().isCheckSpring();
            boolean checkOne = this.burpExtender.tags.getSettingUi().isCheckAll();
            if (filterSpring && checkOne) {
               if (!this.checkRepeat(iHttpRequestResponse)) {
                  if (!this.checkIsSpring.isSpring(iHttpRequestResponse, "", false) && !this.checkIsSpring.isSpring(iHttpRequestResponse, "", true) && !this.checkIsSpring.isSpring(iHttpRequestResponse, "oauth/authorize", false)) {
                     this.burpExtender.stdout.println("未检测到Spring框架" + this.helpers.analyzeRequest(iHttpRequestResponse).getUrl());
                     return null;
                  } else {
                     return this.doScan(iHttpRequestResponse);
                  }
               } else {
                  this.burpExtender.stdout.println("流量已扫描");
                  return null;
               }
            } else if (!filterSpring && checkOne) {
               if (!this.checkRepeat(iHttpRequestResponse)) {
                  return this.doScan(iHttpRequestResponse);
               } else {
                  this.burpExtender.stdout.println("流量已扫描");
                  return null;
               }
            } else if (filterSpring) {
               if (!this.checkIsSpring.isSpring(iHttpRequestResponse, "", false) && !this.checkIsSpring.isSpring(iHttpRequestResponse, "", true) && !this.checkIsSpring.isSpring(iHttpRequestResponse, "oauth/authorize", false)) {
                  this.burpExtender.stdout.println("未检测到Spring框架");
                  return null;
               } else {
                  return this.doScan(iHttpRequestResponse);
               }
            } else {
               return this.doScan(iHttpRequestResponse);
            }
         } catch (InterruptedException | FileNotFoundException var4) {
            var4.printStackTrace();
            this.burpExtender.stdout.println("插件启动失败！！");
            return null;
         }
      }
   }

   public List<IScanIssue> doScan(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException, InterruptedException {
      List<IScanIssue> issues = new ArrayList();
      IRequestInfo requestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
      String url = String.valueOf(requestInfo.getUrl());
      this.Scan.add(this.deelUrl(String.valueOf(requestInfo.getUrl())));
      boolean isErrorCheck = this.burpExtender.tags.getSettingUi().isErrorCheck();
      boolean isReverseCheck = this.burpExtender.tags.getSettingUi().isReverseCheck();
      if (!isErrorCheck && !isReverseCheck) {
         this.burpExtender.stdout.println(String.format("[-] 检测失败： %s", url));
      } else {
         this.burpExtender.stdout.println(String.format("[*] 加载完毕，正在测试： %s", url));
         int id = this.burpExtender.tags.getScannerUi().add("ALL", requestInfo.getMethod(), url, String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()), "[-] 等待扫描结果，请稍后。。。。", iHttpRequestResponse);
         int isVul = true;
         ScanPayload scanPayload = new ScanPayload(this.burpExtender, this.helpers, iHttpRequestResponse);
         int isVul = scanPayload.getIsVul();
         if (isVul == -1) {
            this.burpExtender.tags.getScannerUi().save(id, "ALL", requestInfo.getMethod(), String.valueOf(requestInfo.getUrl()), String.valueOf(this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode()), "[-] 不存在Spring漏洞", iHttpRequestResponse);
         } else {
            IHttpRequestResponse requestResponse;
            if (isVul == 0) {
               issues.add(scanPayload.getVulDetails());
               this.vulName = scanPayload.getVulDetails().getIssueName();
               requestResponse = scanPayload.getVulHttp();
               this.burpExtender.tags.getScannerUi().save(id, "ALL", requestInfo.getMethod(), String.valueOf(requestInfo.getUrl()), String.valueOf(this.helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()), String.format("[?] %s 可能存在漏洞 (需要进一步手动验证)", this.vulName), requestResponse);
            } else if (isVul == 1) {
               issues.add(scanPayload.getVulDetails());
               this.vulName = scanPayload.getVulDetails().getIssueName();
               requestResponse = scanPayload.getVulHttp();
               this.burpExtender.tags.getScannerUi().save(id, "ALL", requestInfo.getMethod(), String.valueOf(requestInfo.getUrl()), String.valueOf(this.helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()), String.format("[+] 存在 %s 漏洞! ! ", this.vulName), requestResponse);
            } else {
               this.burpExtender.stdout.println("未完成检测！");
            }
         }
      }

      return issues;
   }

   public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
      return null;
   }

   public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
      return 0;
   }

   public String deelUrl(String url) {
      return url.startsWith("https") ? url.substring(8, url.indexOf("/", 8)) : url.substring(7, url.indexOf("/", 8));
   }

   public boolean checkRepeat(IHttpRequestResponse httpRequestResponse) {
      IRequestInfo requestInfo = this.helpers.analyzeRequest(httpRequestResponse);
      String url = this.deelUrl(String.valueOf(requestInfo.getUrl()));
      this.burpExtender.stdout.println("获取标识：：" + url);
      this.burpExtender.stdout.println("已获取的标识：：" + this.Scan);
      return this.Scan.contains(url);
   }
}
