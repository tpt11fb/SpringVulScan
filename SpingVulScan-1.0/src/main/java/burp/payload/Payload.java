package burp.payload;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.DnsLog.DnsLogInterface;
import burp.auxiliary.CheckIsSpring;

public interface Payload {
   BurpExtender burpExtender = null;
   IExtensionHelpers helpers = null;
   CheckIsSpring checkIsSpring = null;
   IHttpRequestResponse updataHttp = null;

   IScanIssue doCheckVul(IHttpRequestResponse var1, DnsLogInterface var2);

   IHttpRequestResponse export();
}
