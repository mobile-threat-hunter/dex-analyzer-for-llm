public class K {
    static void a() {}
    static void b() {}
    static void c() {}
    static void custom(String s) {}

    public static void addValues(java.util.Map<String, Object> m) {
        for (String k : m.keySet()) {
            if (k.startsWith("CUSTOM")) {
                custom(k);
                continue;
            }
            switch (k) {
                case "alpha": a(); break;
                case "beta": b(); break;
                case "gamma": c(); break;
                default: custom("unknown " + k);
            }
        }
    }
}
