package fyp;

import java.io.File;
import java.util.List;

// Runs a terminal command (git, syft, grype) from Java and waits for it to finish.
public class CommandRunner {

    public static void run(List<String> command) throws Exception {
        System.out.println("  $ " + String.join(" ", command));

        Process process = new ProcessBuilder(command)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)    // we don't need normal output
                .redirectError(ProcessBuilder.Redirect.INHERIT)     // show errors in the terminal
                .start();

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command failed (exit " + exitCode + "): " + command.get(0));
        }
    }

    public static boolean exists(String path) {
        return new File(path).exists();
    }
}
