package com.talan.auth.util;

public class JWTUtil {
	private JWTUtil() {
		
	}
    public static final String SECRET = "talan-academy-project-java-angular-2022#talan-academy-project-java-angular-2022#talan-academy-project-java-angular-2022#talan-academy-project-java-angular-2022#talan-academy-project-java-angular-2022#talan-academy-project-java-angular-2022#talan-academy-project-java-angular-2022";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 86400000;
    public static final long EXPIRE_REFRESH_TOKEN = 864000000;
}
