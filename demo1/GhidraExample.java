//@category b4tm4n

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import java.util.*;

public class GhidraExample extends GhidraScript {


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

                Iterator<PcodeOpAST> pcodeIter = dRes.getHighFunction().getPcodeOps();

                while (pcodeIter.hasNext()) {
                    PcodeOpAST pcode = pcodeIter.next();

                    if (pcode.getOpcode() == PcodeOp.CALL) {
                        Function callee = api.getFunctionAt(pcode.getInput(0).getAddress());
                        if (sources.contains(callee.getName())) {
                            dataflow(pcode.getOutput());
                        }
                    }
                }
            }

        }
    }

    /**
     * 数据流传播示例，varnode为待被传播的污点，例如getenv的输出varnode
     *
     * @param varnode taint that should focus
     */

    public void dataflow(Varnode varnode) {
        if (varnode == null)
            return;
        Queue<Varnode> workList = new ArrayDeque<>(Set.of(varnode));
        Set<Varnode> processed = Sets.newHashSet();
        while (!workList.isEmpty()) {
            Varnode vn = workList.poll();
            processed.add(vn);
            Iterator<PcodeOp> desIter = vn.getDescendants();
            while (desIter.hasNext()) {
                PcodeOp pcode = desIter.next();
                if (pcode.getOpcode() == PcodeOp.CALL) {
                    /*
                    如果是函数调用，需要判断是否是sink点，如果是sink点，代表存在一条从污点source传播到sink的路径
                     */
                    Function callee = api.getFunctionAt(pcode.getInput(0).getAddress());
                    if (sinks.contains(callee.getName())) {
                        printf("dangerous!taint flow into dangerous function %s\n", callee.getName());
                        continue;
                    }
                    /*
                    如果是需要额外传播数据流的函数，例如strcat、strncat、memcpy等，则进行数据流传播
                     */
                    if (propogation.containsKey(callee.getName())) {
                        workList.addAll(propagate(callee.getName(), pcode, vn));
                    }
                } else {
                    /*
                     * 如果是ghidra的其他IR，这里只以CAST和COPY为例子，则传播数据流
                     */
                    if (pcode.getOpcode() == PcodeOp.CAST || pcode.getOpcode() == PcodeOp.COPY) {

                        if (!processed.contains(pcode.getOutput())) {
                            workList.add(pcode.getOutput());
                        }
                    }
                }


            }
            /*
            获取varnode定义的地方，加入到worklist中
             */
            PcodeOp def = vn.getDef();
            if (def != null) {
                for (Varnode input : def.getInputs()) {
                    if (processed.contains(input))
                        continue;
                    workList.add(input);
                }
            }
            processed.add(vn);
        }
    }


    /**
     * sample propagate function
     *
     * @param callee  function name
     * @param pcodeOp CALL pcode corresponding to callee
     * @param varnode the variable that should propagate dataflow from
     * @return dataflow to Set
     */
    public Set<Varnode> propagate(String callee, PcodeOp pcodeOp, Varnode varnode) {
        if (!propogation.containsKey(callee))
            return Set.of();
        List<Varnode> params = Arrays.stream(pcodeOp.getInputs()).toList();
        if (!params.contains(varnode))
            return Set.of();

        Set<Varnode> forward = Sets.newHashSet();

        int paramIndex = params.indexOf(varnode);
        for (Map.Entry<Integer, Integer> entry : propogation.get(callee).entries()) {
            int toIndex = entry.getKey() + 1;
            int fromIndex = entry.getValue() + 1;
            if (paramIndex == fromIndex) {
                forward.add(params.get(toIndex));
            }
        }

        return forward;
    }
}
