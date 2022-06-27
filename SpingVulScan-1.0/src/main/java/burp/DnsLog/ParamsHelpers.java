package burp.DnsLog;

public class ParamsHelpers {
   public static String getParam(String d, String paramName) {
      if (d != null && d.length() != 0) {
         String value = "test=test;" + d;
         int length = value.length();
         int start = value.indexOf(59) + 1;
         if (start != 0 && start != length) {
            int end = value.indexOf(59, start);
            if (end == -1) {
               end = length;
            }

            while(start < end) {
               int nameEnd = value.indexOf(61, start);
               if (nameEnd != -1 && nameEnd < end && paramName.equals(value.substring(start, nameEnd).trim())) {
                  String paramValue = value.substring(nameEnd + 1, end).trim();
                  int valueLength = paramValue.length();
                  if (valueLength != 0) {
                     if (valueLength > 2 && '"' == paramValue.charAt(0) && '"' == paramValue.charAt(valueLength - 1)) {
                        return paramValue.substring(1, valueLength - 1);
                     }

                     return paramValue;
                  }
               }

               start = end + 1;
               end = value.indexOf(59, start);
               if (end == -1) {
                  end = length;
               }
            }

            return null;
         } else {
            return null;
         }
      } else {
         return null;
      }
   }
}
