import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;

import java.util.List;
import java.util.Stack;

public class GhidraUtil {
    public static DecompInterface getDecompileInterface(Program program) {
        DecompInterface decompInterface = new DecompInterface();
        DecompileOptions decompileOptions = new DecompileOptions();
        decompileOptions.setMaxWidth(2000);
//        decompileOptions.setIfElseBraceFormat();
        decompileOptions.setNoCastPrint(true);
        decompInterface.setOptions(decompileOptions);
        if (decompInterface.openProgram(program)) {
            return decompInterface;
        }
        throw new RuntimeException("decompile interface open fail.");
    }

    public static FlatProgramAPI getApi(Program program) {
        return new FlatProgramAPI(program);
    }

    public static ClangSyntaxToken getMatchToken(List<ClangToken> tokens, ClangSyntaxToken token2match) {

        if (token2match == null || !tokens.contains(token2match))
            return null;
        Stack<ClangSyntaxToken> stack = new Stack<>();
        for (int i = tokens.indexOf(token2match); i < tokens.size(); i++) {

            ClangToken token = tokens.get(i);
            if (token instanceof ClangSyntaxToken cyt) {
                if (cyt.getText().equals("(")) {
                    stack.push(cyt);
                } else if (cyt.getText().equals(")")) {
                    if (!stack.isEmpty()) {
                        ClangSyntaxToken pop = stack.pop();
                        if (stack.isEmpty()) {
                            return cyt;
                        }
                    }
                }
            }

        }
        return null;
    }
}
