package com.kyuth.naver.login.crawler.common;

import java.util.HashMap;
import java.util.Map;

public class Utility {

    /**
     * query String to Map
     *
     * @param str url query String 데이터
     * @return {@link Map}
     *
     * <p>
     * @author brandon
     * @since 2021-07-27
     */
    public static Map<String, String> convertParamData(String str) {

        HashMap<String, String> map = new HashMap<>();

        String[] params = str.split("&");
        for (String param : params) {
            String[] keyValue = param.split("=");
            if (keyValue.length >= 2) {
                map.put(keyValue[0], keyValue[1]);
            } else {
                map.put(keyValue[0], "");

            }
        }
        return map;
    }

}
