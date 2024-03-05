//@category b4tm4n

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class GhidraDecompileExample extends GhidraScript {
    public static Set<String> sources = Set.of("getenv");
    public static Set<String> sinks = Set.of("execl");
    public static Map<String, MultiValuedMap<Integer, Integer>> propogation = Maps.newHashMap();

    static {
        MultiValuedMap<Integer, Integer> map = new ArrayListValuedHashMap<>();
        map.put(0, 1);
        propogation.put("strncat", map);
    }

    public static FlatProgramAPI api;
    DecompInterface deIfc;

    @Override
    protected void run() throws Exception {
        api = GhidraUtil.getApi(currentProgram);
        deIfc = GhidraUtil.getDecompileInterface(currentProgram);
        Function function = api.getFunctionContaining(currentAddress);
        if (function != null) {
            DecompileResults dRes = deIfc.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (dRes.decompileCompleted()) {
                ArrayList<ClangLine> lines = DecompilerUtils.toLines(dRes.getCCodeMarkup());
                for (ClangLine line : lines) {
                    List<ClangToken> tokens = line.getAllTokens();
                    for (ClangToken token : tokens) {
                        if (token instanceof ClangFuncNameToken cft) {
                            if (sources.contains(cft.getText())) {
                                Multimap<Integer, ClangVariableToken> id2params = resolveCallsite(cft);
                                dataflow(lines, id2params.get(-1).stream().toList().get(0));
                            }
                        }
                    }

                }
            }
        }
    }

    /**
     * 解析函数调用范例
     *
     * @param cft
     * @return 下标to参数的map
     */

    public Multimap<Integer, ClangVariableToken> resolveCallsite(ClangFuncNameToken cft) {

        Multimap<Integer, ClangVariableToken> id2param = ArrayListMultimap.create();

        List<ClangToken> tokens = cft.getLineParent().getAllTokens();
        ClangSyntaxToken close = null;
        ClangSyntaxToken open = null;
        for (int i = tokens.indexOf(cft) + 1; i < tokens.size(); i++) {
            if (tokens.get(i) instanceof ClangSyntaxToken cst && cst.getText().equals("(")) {
                open = cst;
                break;
            }
        }
        close = GhidraUtil.getMatchToken(tokens, open);
        if (close == null) {
            return id2param;
        }
        int index = 0;
        for (int i = tokens.indexOf(open) + 1; i < tokens.indexOf(close); i++) {
            ClangToken clangToken = tokens.get(i);
            if (clangToken instanceof ClangVariableToken cvt) {
                id2param.put(index, cvt);
            } else if (clangToken.getText().equals(",")) {
                index++;
            }
        }

        for (int i = 0; i < tokens.indexOf(cft); i++) {
            ClangToken token = tokens.get(i);
            if (token instanceof ClangVariableToken cvt) {
                id2param.put(-1, cvt);
            }
        }


        return id2param;
    }

    /**
     * 追踪给定的token范例
     *
     * @param clines      ClangLine 集合
     * @param token2trace 等待追踪的污点token
     */

    public void dataflow(List<ClangLine> clines, ClangVariableToken token2trace) {
        Set<ClangVariableToken> same = Sets.newHashSet();
        Set<ClangVariableToken> forward = Sets.newHashSet();
        int startLine = clines.indexOf(token2trace.getLineParent());
        /*
         *  获取与污点相关的所有变量
         */
        for (int i = startLine + 1; i < clines.size(); i++) {
            ArrayList<ClangToken> tokens = clines.get(i).getAllTokens();
            tokens.forEach(t -> {
                if (t instanceof ClangVariableToken cvt && t.getText().equals(token2trace.getText())) {
                    same.add(cvt);
                } else if (t instanceof ClangFuncNameToken cft) {
                    if (propogation.containsKey(cft.getText())) {
                        {
                            forward.addAll(propagate(cft, token2trace));
                        }
                    }

                }
            });
        }


        /*

         */
        Set<ClangVariableToken> relatedToken = Sets.newHashSet(same);
        relatedToken.addAll(forward);
        for (int i = startLine + 1; i < clines.size(); i++) {
            ArrayList<ClangToken> tokens = clines.get(i).getAllTokens();
            tokens.forEach(t -> {
                if (t instanceof ClangFuncNameToken cft) {
                    if (sinks.contains(cft.getText()) && resolveCallsite(cft).values().stream().anyMatch(v -> relatedToken.contains(v.getText()))) {
                        {
                            println("Dangerous");
                        }
                    }

                }
            });
        }

    }

    /**
     * 传播数据流
     *
     * @param cft
     * @param token2progate
     * @return
     */
    public Set<ClangVariableToken> propagate(ClangFuncNameToken cft, ClangVariableToken token2progate) {
        Multimap<Integer, ClangVariableToken> idx2param = resolveCallsite(cft);

        String callee = cft.getText();
        if (!propogation.containsKey(callee)) {
            return Set.of();
        }
        int paramIndex = -1;
        for (Map.Entry<Integer, ClangVariableToken> entry : idx2param.entries()) {
            if (entry.getValue().getText().equals(token2progate.getText())) {
                paramIndex = entry.getKey();
            }
        }
        Set<ClangVariableToken> forward = Sets.newHashSet();


        for (Map.Entry<Integer, Integer> entry : propogation.get(callee).entries()) {
            int toIndex = entry.getKey();
            int fromIndex = entry.getValue();
            if (paramIndex == fromIndex) {
                forward.addAll(idx2param.get(toIndex));
            }
        }

        return forward;
    }

}
