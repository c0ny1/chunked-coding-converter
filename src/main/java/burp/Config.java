package burp;


public class Config {
    private static Integer min_chunked_len = 1;
    private static Integer max_chunked_len = 3;
    private static boolean addComment = true;
    private static Integer min_comment_len = 5;
    private static Integer max_comment_len = 25;
    private static boolean act_on_all_tools = false;
    private static boolean act_on_target = false;
    private static boolean act_on_proxy = false;
    private static boolean act_on_spider = false;
    private static boolean act_on_intruder = false;
    private static boolean act_on_repeater = false;
    private static boolean act_on_scanner = false;
    private static boolean act_on_extender = false;
    private static boolean act_on_sequencer = false;

    public static Integer getMin_chunked_len() {
        String val = BurpExtender.callbacks.loadExtensionSetting("min_chunked_len");
        try {
            return Integer.valueOf(val);
        }catch(Exception e){
            return min_chunked_len;
        }
    }

    public static void setMin_chunked_len(Integer min_chunked_len) {
        BurpExtender.callbacks.saveExtensionSetting("min_chunked_len", String.valueOf(min_chunked_len));
        Config.min_chunked_len = min_chunked_len;
    }

    public static Integer getMax_chunked_len() {
        String val = BurpExtender.callbacks.loadExtensionSetting("max_chunked_len");
        BurpExtender.stdout.println("[+] max_chunked_len: " + val);
        try {
            return Integer.valueOf(val);
        }catch(Exception e){
            return max_chunked_len;
        }
    }

    public static void setMax_chunked_len(Integer max_chunked_len) {
        BurpExtender.callbacks.saveExtensionSetting("max_chunked_len", String.valueOf(max_chunked_len));
        Config.max_chunked_len = max_chunked_len;
    }

    public static boolean isAddComment() {
        String val = BurpExtender.callbacks.loadExtensionSetting("addComment");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return addComment;
        }
    }

    public static void setAddComment(boolean addComment) {
        BurpExtender.callbacks.saveExtensionSetting("addComment", String.valueOf(addComment));
        Config.addComment = addComment;
    }

    public static Integer getMin_comment_len() {
        String val = BurpExtender.callbacks.loadExtensionSetting("min_comment_len");
        try {
            return Integer.valueOf(val);
        }catch(Exception e){
            return min_comment_len;
        }
    }

    public static void setMin_comment_len(Integer min_comment_len) {
        BurpExtender.callbacks.saveExtensionSetting("min_comment_len", String.valueOf(min_comment_len));
        Config.min_comment_len = min_comment_len;
    }

    public static Integer getMax_comment_len() {
        String val = BurpExtender.callbacks.loadExtensionSetting("max_comment_len");
        try {
            return Integer.valueOf(val);
        }catch(Exception e){
            return max_comment_len;
        }
    }

    public static void setMax_comment_len(Integer max_comment_len) {
        BurpExtender.callbacks.saveExtensionSetting("max_comment_len", String.valueOf(max_comment_len));
        Config.max_comment_len = max_comment_len;
    }

    public static boolean isAct_on_all_tools() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_all_tools");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_all_tools;
        }
    }

    public static void setAct_on_all_tools(boolean act_on_all_tools) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_all_tools", String.valueOf(act_on_all_tools));
        Config.act_on_all_tools = act_on_all_tools;
    }

    public static boolean isAct_on_target() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_target");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_target;
        }
    }

    public static void setAct_on_target(boolean act_on_target) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_target", String.valueOf(act_on_target));
        Config.act_on_target = act_on_target;
    }

    public static boolean isAct_on_proxy() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_proxy");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_proxy;
        }
    }

    public static void setAct_on_proxy(boolean act_on_proxy) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_proxy", String.valueOf(act_on_proxy));
        Config.act_on_proxy = act_on_proxy;
    }

    public static boolean isAct_on_spider() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_spider");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_spider;
        }
    }

    public static void setAct_on_spider(boolean act_on_spider) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_spider", String.valueOf(act_on_spider));
        Config.act_on_spider = act_on_spider;
    }

    public static boolean isAct_on_intruder() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_intruder");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_intruder;
        }
    }

    public static void setAct_on_intruder(boolean act_on_intruder) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_intruder", String.valueOf(act_on_intruder));
        Config.act_on_intruder = act_on_intruder;
    }

    public static boolean isAct_on_repeater() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_repeater");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_repeater;
        }
    }

    public static void setAct_on_repeater(boolean act_on_repeater) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_repeater", String.valueOf(act_on_repeater));
        Config.act_on_repeater = act_on_repeater;
    }

    public static boolean isAct_on_scanner() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_scanner");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_scanner;
        }
    }

    public static void setAct_on_scanner(boolean act_on_scanner) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_scanner", String.valueOf(act_on_scanner));
        Config.act_on_scanner = act_on_scanner;
    }

    public static boolean isAct_on_extender() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_extender");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_extender;
        }
    }

    public static void setAct_on_extender(boolean act_on_extender) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_extender", String.valueOf(act_on_extender));
        Config.act_on_extender = act_on_extender;
    }

    public static boolean isAct_on_sequencer() {
        String val = BurpExtender.callbacks.loadExtensionSetting("act_on_sequencer");
        try {
            return Boolean.valueOf(val);
        }catch(Exception e){
            return act_on_sequencer;
        }
    }

    public static void setAct_on_sequencer(boolean act_on_sequencer) {
        BurpExtender.callbacks.saveExtensionSetting("act_on_sequencer", String.valueOf(act_on_sequencer));
        Config.act_on_sequencer = act_on_sequencer;
    }
}
