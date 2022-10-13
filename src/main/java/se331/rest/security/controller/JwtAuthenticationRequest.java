package se331.rest.security.controller;

import java.io.Serializable;


public class JwtAuthenticationRequest implements Serializable {

    private static final long serialVersionUID = -8445943548965154778L;

    private String username;
    private String password;
    private String newPassword;
    private String token;
    private String urlSetPassword;

    public JwtAuthenticationRequest() {
        super();
    }

    public JwtAuthenticationRequest(String username, String password, String newPassword, String token, String urlSetPassword) {
        this.setUsername(username);
        this.setPassword(password);
        this.setNewPassword(newPassword);
        this.setToken(token);
        this.setUrlSetPassword(urlSetPassword);
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUrlSetPassword() {
        return urlSetPassword;
    }

    public void setUrlSetPassword(String urlSetPassword) {
        this.urlSetPassword = urlSetPassword;
    }
}
