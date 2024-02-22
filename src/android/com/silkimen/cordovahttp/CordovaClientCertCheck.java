package com.silkimen.cordovahttp;

import android.app.Activity;

import android.security.KeyChain;
import android.security.KeyChainException;

import org.apache.cordova.CallbackContext;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class CordovaClientCertCheck implements Runnable {
    private String aliasString;
    private Activity activity;
    private CallbackContext callbackContext;
    public CordovaClientCertCheck(final String aliasString, final Activity activity, final CallbackContext callbackContext) {
        this.aliasString = aliasString;
        this.activity = activity;
        this.callbackContext = callbackContext;
    }

    @Override
    public void run() {
        try {
            this.checkClientCertValidity();
        } catch ( JSONException e) {
            callbackContext.error(e.getMessage());
        }
    }

    private void checkClientCertValidity() throws JSONException {
        final String VALIDITY = "validity";
        final String EXISTS = "exists";

        JSONObject result = new JSONObject();
        X509Certificate[] certChain;

        try {
            certChain = KeyChain.getCertificateChain(this.activity.getApplicationContext(), aliasString);
        } catch (KeyChainException | InterruptedException e){
            // prior to Android Q/10, if there is no certificate for given alias or no permission to
            // access the cert a KeyChainException with a Throwable of type IllegalStateException is thrown
            Throwable throwable = e.getCause();
            if(e instanceof KeyChainException && throwable != null && throwable instanceof IllegalStateException ) {
                result.put(VALIDITY, false);
                result.put(EXISTS, false);
                callbackContext.success(result);
                return;
            }

            callbackContext.error(e.getMessage());
            return;
        }

        if(certChain == null){
            result.put(VALIDITY, false);
            result.put(EXISTS, false);
            callbackContext.success(result);
            return;
        }

        for (X509Certificate cert : certChain) {
            try {
                cert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e ){
                result.put(VALIDITY, false);
                result.put(EXISTS, true);
                callbackContext.success(result);
                return;
            }
        }


        result.put(VALIDITY, true);
        result.put(EXISTS, true);
        callbackContext.success(result);
    }
}
