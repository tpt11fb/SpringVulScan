package burp.auxiliary;

import burp.BurpExtender;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;

public class YamlReader {
   private BurpExtender burpExtender;
   private static Map<String, Map<String, Object>> properties = new HashMap();

   public YamlReader(BurpExtender burpExtender) throws FileNotFoundException {
      this.burpExtender = burpExtender;
      String p = this.getRunFilePath() + "config\\config.yml";
      File f = new File(p);
      properties = (Map)(new Yaml()).load((InputStream)(new FileInputStream(f)));
      this.burpExtender.stdout.println(p + " 配置文件加载完毕！");
   }

   public YamlReader() throws FileNotFoundException {
      String p = "E:\\Tools\\burp\\extend开发\\SpingVulScan\\target\\config\\config.yml";
      File f = new File(p);
      properties = (Map)(new Yaml()).load((InputStream)(new FileInputStream(f)));
   }

   public Object getValueByKey(String key) {
      String separator = ".";
      String[] separatorKeys = null;
      if (!key.contains(separator)) {
         return properties.get(key);
      } else {
         separatorKeys = key.split("\\.");
         Object finalValue = new HashMap();

         for(int i = 0; i < separatorKeys.length - 1; ++i) {
            if (i == 0) {
               finalValue = (Map)properties.get(separatorKeys[i]);
            } else {
               if (finalValue == null) {
                  break;
               }

               finalValue = (Map)((Map)finalValue).get(separatorKeys[i]);
            }
         }

         return finalValue == null ? null : ((Map)finalValue).get(separatorKeys[separatorKeys.length - 1]);
      }
   }

   private String getRunFilePath() {
      String path = "";
      int lastIndex = this.burpExtender.callbacks.getExtensionFilename().lastIndexOf(File.separator);
      path = this.burpExtender.callbacks.getExtensionFilename().substring(0, lastIndex) + File.separator;
      return path;
   }
}
