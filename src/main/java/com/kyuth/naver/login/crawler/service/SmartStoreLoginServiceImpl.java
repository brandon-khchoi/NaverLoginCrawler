package com.kyuth.naver.login.crawler.service;

import com.kyuth.naver.login.crawler.common.JsRsaEncrypt;
import com.kyuth.naver.login.crawler.common.LZString;
import com.kyuth.naver.login.crawler.common.Utility;
import lombok.extern.slf4j.Slf4j;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class SmartStoreLoginServiceImpl implements LoginService {

    private String id, pw;

    public SmartStoreLoginServiceImpl() {
    }

    public SmartStoreLoginServiceImpl(String id, String pw) {
        this.id = id;
        this.pw = pw;
    }

    public Connection.Response login(String id, String pw) {
        return getNaverLoginResponse(id, pw);
    }

    @Override
    public Connection.Response login() throws Exception {
        if ("".equals(id) || "".equals(pw)) {
            throw new Exception("id or pw가 공백일 수 없습니다. (생성자 오류)");
        }
        return getNaverLoginResponse(id, pw);
    }

    /**
     * dynamicKey 값 획득 method
     * 스마트스토어 로그인 세션 획득 및 bvsd 데이터에 사용
     *
     * @return {@link String}
     * <p>
     * @author brandon
     * @since 2021-07-27
     */
    private String getDynamicKey() throws IOException {

        Map<String, String> headers = new HashMap<String, String>() {{
            put("origin", "https://nid.naver.com");
        }};
        Connection.Response loginViewResponse = Jsoup.connect("https://nid.naver.com/nidlogin.login")
                .method(Connection.Method.GET)
                .userAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
                .referrer("https://nid.naver.com/nidlogin.login")
                .headers(headers)
                .execute();

        return loginViewResponse.parse().getElementById("dynamicKey").val();
    }

    /**
     * 스마트스토어 로그인 세션 정보
     *
     * @param dynamicKey getDynamicKey() method return 값
     * @return {@link String} - sessionKey, encName, publicModulusKey, publicExponentKey 로 구성 ","로 split 하여 사용
     * <p>
     * @author brandon
     * @since 2021-07-27
     */
    private String getNaverSessionInfo(String dynamicKey) throws IOException {

        Map<String, String> headers = new HashMap<String, String>() {{
            put("origin", "https://nid.naver.com");
        }};

        log.info("dynamicKey : {}", dynamicKey);
        Connection.Response naverSessionInfo = Jsoup.connect("https://nid.naver.com/dynamicKey/" + dynamicKey)
                .method(Connection.Method.GET)
                .userAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
                .referrer("https://nid.naver.com/nidlogin.login")
                .headers(headers)
                .execute();

        log.info("sessionInfo : {} ", naverSessionInfo.body());

        return naverSessionInfo.body();
    }

    /**
     * RSA 암호화할 target 데이터 생성
     *
     * @param sessionKey 세션 키
     * @param id         계정
     * @param password   비밀번호
     * @return {@link String}
     * <p>
     * @author brandon
     * @since 2021-07-27
     */
    private String getEncryptTarget(String sessionKey, String id, String password) {

        return (char) sessionKey.length() +
                sessionKey +
                (char) id.length() +
                id +
                (char) password.length() +
                password;
    }

    /**
     * 스마트스토어 로그인 쿠키 크롤링
     * 로그인 실패시 null return
     *
     * @param id 계정
     * @param password 비밀번호
     * @return {@link Connection.Response} cookies() 메소드 로그인 쿠키 담겨있음.
     * <p>
     * @author brandon
     * @since 2021-07-27
     */
    public Connection.Response getNaverLoginResponse(String id, String password) {

        try {
            String dynamicKey = getDynamicKey();

            String naverSessionInfo = getNaverSessionInfo(dynamicKey);
            log.info("naverSessionInfo : {}", naverSessionInfo);

            String[] naverSessionInfoArr = naverSessionInfo.split(",");

            if (naverSessionInfoArr.length < 4) {
                return null;
            } else {
                String sessionKey = naverSessionInfoArr[0];
                String encName = naverSessionInfoArr[1];
                String modulus = naverSessionInfoArr[2];
                String exponent = naverSessionInfoArr[3];

                log.info("sessionKey : {}", sessionKey);
                log.info("encName : {}", encName);
                log.info("publicModulusKey : {}", modulus);
                log.info("publicExponentKey : {}", exponent);

                String encryptTarget = getEncryptTarget(sessionKey, id, password);
                log.info("rsaTarget : {}", encryptTarget);

                JsRsaEncrypt rsa = new JsRsaEncrypt(modulus, exponent);
                String encPw = rsa.encrypt(encryptTarget);

                log.info("encPw : {}", encPw);
                log.info("encName : {}", encName);
                log.info("dynamicKey : {}", dynamicKey);

                String uuid = UUID.randomUUID().toString();

                //ncaptcha 우회 데이터
                String encData = "{\"a\":\""+uuid+"\",\"b\":\"1.3.4\",\"d\":[{\"i\":\"id\",\"b\":{\"a\":[\"0,"+id+"\"]},\"d\":\""+id+"\",\"e\":false,\"f\":false},{\"i\":\""+ password+"@\",\"e\":true,\"f\":false}],\"h\":\"1f\",\"i\":{\"a\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36\"}}";

                String bvsd = "{\"uuid\":\"" + uuid + "\",\"encData\":\"" + LZString.compressToEncodedURIComponent(encData) + "\"}";

                String param = "bvsd=" + bvsd +
                        "&dynamicKey=" + dynamicKey +
                        "&enctp=1" +
                        "&encpw=" + encPw +
                        "&encnm=" + encName +
                        "&svctuype=1" +
                        "&smart_LEVEL=1" +
                        "&locale=ko_KR" +
                        "&url=https%3A%2F%2Fsell.smartstore.naver.com%2F%23%2FnaverLoginCallback%3Furl%3Dhttps%253A%252F%252Fsell.smartstore.naver.com%252F%2523" +
                        "&id=" +
                        "&pw=";

                //로그인 요청
                Connection.Response loginResponse = Jsoup.connect("https://nid.naver.com/nidlogin.login")
                        .method(Connection.Method.POST)
                        .header("host", "nid.naver.com")
                        .userAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
                        .referrer("https://nid.naver.com/nidlogin.login")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .data(Utility.convertParamData(param))
                        .execute();

                if (!loginResponse.cookies().containsKey("NID_AUT") || !loginResponse.cookies().containsKey("NID_SES")) {
                    return null;
                }

                log.info("{} - SmartStore Login RESPONSE : {}", id, loginResponse.body());
                log.info("{} - SmartStore Login Cookies : {}", id, loginResponse.cookies());

                return loginResponse;
            }
        } catch (Exception e) {
            log.info("{} - SmartStore Login Error {}", id, e.getMessage());
            return null;
        }

    }

}
