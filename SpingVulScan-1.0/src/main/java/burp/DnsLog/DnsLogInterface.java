package burp.DnsLog;

public interface DnsLogInterface {
   String getTempDomain();

   String getBodyContent() throws InterruptedException;

   boolean checkResult() throws InterruptedException;

   String outExport();

   void export();
}
