package burp.auxiliary;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ReadFile {
   private final String filePath;

   public ReadFile(String filePath) {
      this.filePath = filePath;
   }

   public List<String> littleFile() throws IOException {
      Path path = Paths.get(this.filePath);
      byte[] bytes = Files.readAllBytes(path);
      return Files.readAllLines(path, StandardCharsets.UTF_8);
   }

   public Set<String> bigFile() throws IOException {
      File file = new File(this.filePath);
      FileInputStream fis = new FileInputStream(file);
      InputStreamReader isr = new InputStreamReader(fis);
      BufferedReader br = new BufferedReader(isr);
      HashSet content = new HashSet();

      String line;
      while((line = br.readLine()) != null) {
         content.add(line);
      }

      br.close();
      return content;
   }
}
