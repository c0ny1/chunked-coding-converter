package burp.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class DateUtil {
    private static SimpleDateFormat df = new SimpleDateFormat("YYYY/MM/dd HH:mm:ss");
    public static double betweenMs(String startTime, String nowTime){
        double diff = 0;
        try {
            double NTime = (double)df.parse(nowTime).getTime();
            //从对象中拿到时间
            double OTime = (double)df.parse(startTime).getTime();
            diff = NTime-OTime;
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return diff;
    }

    public static String getNowTime(){
        return df.format(new Date());
    }

    public static String ms2str(double ms){
        String res = null;
        if(ms >= 1000*60){
            double m = ms/(1000*60);
            res = String.format("%.2fm",m);
        }else if(ms >= 1000){
            double s = ms/1000;
            res = String.format("%.1fs",s);
        }else{
            res = String.format("%.1fms",ms);
        }
        return res;
    }
}
