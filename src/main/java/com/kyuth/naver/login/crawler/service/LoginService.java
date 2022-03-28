package com.kyuth.naver.login.crawler.service;

import org.jsoup.Connection;

public interface LoginService {

    Connection.Response login() throws Exception;

}
