/*
 * Copyright (C) 2013-2017 microG Project Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test;

import static android.os.Build.VERSION.SDK_INT;
import static android.os.Build.VERSION_CODES.GINGERBREAD_MR1;
import static android.os.Build.VERSION_CODES.HONEYCOMB;
import static android.os.Build.VERSION_CODES.LOLLIPOP;
import static android.telephony.TelephonyManager.SIM_STATE_UNKNOWN;
import static android.view.View.INVISIBLE;
import static android.view.View.VISIBLE;
import static android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT;
import static org.microg.gms.common.Constants.GMS_VERSION_CODE;

import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.RelativeLayout;

import androidx.webkit.WebViewClientCompat;

import com.google.android.gms.R;

import org.json.JSONArray;
import org.microg.gms.auth.AuthConstants;
import org.microg.gms.checkin.CheckinManager;
import org.microg.gms.checkin.LastCheckinInfo;
import org.microg.gms.profile.Build;
import org.microg.gms.profile.ProfileManager;

import java.io.IOException;
import java.util.Locale;

abstract class AssistantActivity2 extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.login_assistant2);
    }
}

public class LoginActivity extends AssistantActivity2 {
    public static final String TMPL_NEW_ACCOUNT = "new_account";
    public static final String EXTRA_TMPL = "tmpl";
    public static final String EXTRA_EMAIL = "email";
    public static final String EXTRA_TOKEN = "masterToken";
    public static final int STATUS_BAR_DISABLE_BACK = 0x00400000;
    private static final String TAG = "GmsAuthLoginBrowser";
    private static final String EMBEDDED_SETUP_URL = "https://accounts.google.com/EmbeddedSetup";
    private static final String PROGRAMMATIC_AUTH_URL = "https://accounts.google.com/o/oauth2/programmatic_auth";
    private static final String GOOGLE_SUITE_URL = "https://accounts.google.com/signin/continue";
    private static final String MAGIC_USER_AGENT = " MinuteMaid";
    private static final String COOKIE_OAUTH_TOKEN = "oauth_token";
    //    private final DroidGuardHandler dgHandler = new DroidGuardHandler(this);
    private WebView webView;
    private String accountType;
    private InputMethodManager inputMethodManager;
    private ViewGroup authContent;
    public AccountAuthenticatorResponse response;

    @SuppressLint("AddJavascriptInterface")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        accountType = AuthConstants.DEFAULT_ACCOUNT_TYPE;
        inputMethodManager = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
        webView = createWebView(this);
        webView.addJavascriptInterface(new JsBridge(), "mm");
        authContent = (ViewGroup) findViewById(R.id.auth_content2);
        ((ViewGroup) findViewById(R.id.auth_root2)).addView(webView);
        webView.setWebViewClient(new WebViewClientCompat() {
            @Override
            public void onPageFinished(WebView view, String url) {
                Log.d(TAG, "pageFinished: " + view.getUrl());
                Uri uri = Uri.parse(view.getUrl());

                // Begin login.
                // Only required if client code does not invoke showView() via JSBridge
                if ("identifier".equals(uri.getFragment()) || uri.getPath().endsWith("/identifier"))
                    runOnUiThread(() -> webView.setVisibility(VISIBLE));

                // Normal login.
                if ("close".equals(uri.getFragment()))
                    closeWeb(false);

                // Google Suite login.
                if (url.startsWith(GOOGLE_SUITE_URL))
                    closeWeb(false);

                // IDK when this is called.
                if (url.startsWith(PROGRAMMATIC_AUTH_URL))
                    closeWeb(true);
            }
        });
        init();
//        if (getIntent().hasExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE)) {
//            Object tempObject = getIntent().getExtras().get("accountAuthenticatorResponse");
//            if (tempObject instanceof AccountAuthenticatorResponse) {
//                response = (AccountAuthenticatorResponse) tempObject;
//            }
//        }
//        if (getIntent().hasExtra(EXTRA_TOKEN)) {
//            if (getIntent().hasExtra(EXTRA_EMAIL)) {
//                AccountManager accountManager = AccountManager.get(this);
//                Account account = new Account(getIntent().getStringExtra(EXTRA_EMAIL), accountType);
//                accountManager.addAccountExplicitly(account, getIntent().getStringExtra(EXTRA_TOKEN), null);
//                if (isAuthVisible(this) && SDK_INT >= 26) {
//                    accountManager.setAccountVisibility(account, PACKAGE_NAME_KEY_LEGACY_NOT_VISIBLE, VISIBILITY_USER_MANAGED_VISIBLE);
//                }
//                retrieveGmsToken(account);
//            } else {
//                retrieveRtToken(getIntent().getStringExtra(EXTRA_TOKEN));
//            }
//        } else {
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        if(response != null){
            response.onError(AccountManager.ERROR_CODE_CANCELED, "Canceled");
        }
    }

    private void init() {
        authContent.removeAllViews();
        CookieManager.getInstance().setAcceptCookie(true);
        if (SDK_INT >= LOLLIPOP) {
            CookieManager.getInstance().removeAllCookies(value -> start());
        } else {
            //noinspection deprecation
            CookieManager.getInstance().removeAllCookie();
            start();
        }
    }

    private WebView createWebView(Context context) {
        WebView webView = new WebView(context);
        if (SDK_INT < LOLLIPOP) {
            webView.setVisibility(VISIBLE);
        } else {
            webView.setVisibility(INVISIBLE);
        }
        webView.setLayoutParams(new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        webView.setBackgroundColor(Color.TRANSPARENT);
        prepareWebViewSettings(webView.getSettings());
        return webView;
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void prepareWebViewSettings(WebSettings settings) {
//        ProfileManager.ensureInitialized(this);
//        settings.setUserAgentString(Build.INSTANCE.generateWebViewUserAgentString(settings.getUserAgentString()) + MAGIC_USER_AGENT);
        settings.setUserAgentString( "Mozilla/5.0 (Linux; Android 10; MI 6 Build/QQ3A.200805.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/90.0.4430.82 Mobile Safari/537.36 MinuteMaid");
        settings.setJavaScriptEnabled(true);
        settings.setSupportMultipleWindows(false);
        settings.setSaveFormData(false);
        settings.setAllowFileAccess(false);
        settings.setDatabaseEnabled(false);
        settings.setNeedInitialFocus(false);
        settings.setUseWideViewPort(false);
        settings.setSupportZoom(false);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
    }

    private void start() {
        new Thread(() -> {
            Runnable next;
            next = checkin(false) ? this::loadLoginPage : () -> showError(R.string.auth_general_error_desc);
            LoginActivity.this.runOnUiThread(next);
        }).start();

    }

    private void showError(int errorRes) {
        Log.e(TAG, "showError: " + errorRes);
    }

    private void loadLoginPage() {
        String tmpl = getIntent().hasExtra(EXTRA_TMPL) ? getIntent().getStringExtra(EXTRA_TMPL) : TMPL_NEW_ACCOUNT;
        webView.loadUrl(buildUrl(tmpl, Locale.getDefault()));
    }

    protected void runScript(String js) {
        runOnUiThread(() -> webView.loadUrl("javascript:" + js));
    }

    private void closeWeb(boolean programmaticAuth) {
        runOnUiThread(() -> webView.setVisibility(INVISIBLE));
        String cookies = CookieManager.getInstance().getCookie(programmaticAuth ? PROGRAMMATIC_AUTH_URL : EMBEDDED_SETUP_URL);
        String[] temp = cookies.split(";");
        for (String ar1 : temp) {
            if (ar1.trim().startsWith(COOKIE_OAUTH_TOKEN + "=")) {
                String[] temp1 = ar1.split("=");
                retrieveRtToken(temp1[1]);
                return;
            }
        }
    }

    private void retrieveRtToken(String oAuthToken) {
//        new AuthRequest().fromContext()
//                .appIsGms()
//                .callerIsGms()
//                .service("ac2dm")
//                .token(oAuthToken).isAccessToken()
//                .addAccount()
//                .getAccountId()
//                .droidguardResults(null /*TODO*/)
//                .getResponseAsync(new HttpFormClient.Callback<AuthResponse>() {
//                    @Override
//                    public void onResponse(AuthResponse response) {
//                        Account account = new Account(response.email, accountType);
//                        DeviceInfo.inst.accountCookiesManger.createAccount(account);
//                        DeviceInfo.inst.accountCookiesManger.setToken(account, response.token);
//                        DeviceInfo.inst.accountCookiesManger.setKv(account, "SID", response.Sid);
//                        DeviceInfo.inst.accountCookiesManger.setKv(account, "LSID", response.LSid);
//                        DeviceInfo.inst.accountCookiesManger.setKv(account, "flags", "1");
//                        DeviceInfo.inst.accountCookiesManger.setKv(account, "services", response.services);
//                        DeviceInfo.inst.accountCookiesManger.setKv(account, "oauthAccessToken", "1");
//                        DeviceInfo.inst.accountCookiesManger.setKv(account, "firstName", response.firstName);
//                        DeviceInfo.inst.accountCookiesManger.setKv(account, "lastName", response.lastName);
//                        if (!TextUtils.isEmpty(response.accountId))
//                            DeviceInfo.inst.accountCookiesManger.setKv(account, "GoogleUserId", response.accountId);
//
//                        retrieveGmsToken(account);
//                        setResult(RESULT_OK);
//                    }
//
//                    @Override
//                    public void onException(Exception exception) {
//                        Log.w(TAG, "onException", exception);
//                        runOnUiThread(() -> {
//                            showError(R.string.auth_general_error_desc);
//                        });
//                    }
//                });
    }

    private void returnSuccessResponse(Account account) {
        if (response != null) {
            Bundle bd = new Bundle();
            bd.putString(AccountManager.KEY_ACCOUNT_NAME, account.name);
            bd.putBoolean("new_account_created", false);
            bd.putString(AccountManager.KEY_ACCOUNT_TYPE, accountType);
            response.onResult(bd);
        }
    }

    private void retrieveGmsToken(final Account account) {
//        final AuthManager authManager = new AuthManager(this, account.name, GMS_PACKAGE_NAME, "ac2dm");
//        authManager.setPermitted(true);
//        new AuthRequest().fromContext()
//                .appIsGms()
//                .callerIsGms()
//                .service(authManager.getService())
//                .email(account.name)
//                .token(DeviceInfo.inst.accountCookiesManger.getAccountCookies(account).token)
//                .systemPartition(true)
//                .hasPermission(true)
//                .addAccount()
//                .getAccountId()
//                .getResponseAsync(new HttpFormClient.Callback<AuthResponse>() {
//                    @Override
//                    public void onResponse(AuthResponse response) {
//                        authManager.storeResponse(response);
//                        String accountId = PeopleManager.loadUserInfo(LoginActivity.this, account);
//                        if (!TextUtils.isEmpty(accountId))
//                            DeviceInfo.inst.accountCookiesManger.setKv(account, "GoogleUserId", accountId);
//                        checkin(true);
//                        returnSuccessResponse(account);
//                        finish();
//                    }
//
//                    @Override
//                    public void onException(Exception exception) {
//                        Log.w(TAG, "onException", exception);
//                        runOnUiThread(() -> {
//                            showError(R.string.auth_general_error_desc);
//                        });
//                    }
//                });
    }

    private boolean checkin(boolean force) {
        try {
            CheckinManager.checkin(this, force);
            return true;
        } catch (IOException e) {
            Log.w(TAG, "Checkin failed", e);
        }
        return false;
    }

    private static String buildUrl(String tmpl, Locale locale) {
        return Uri.parse(EMBEDDED_SETUP_URL).buildUpon()
                .appendQueryParameter("source", "android")
                .appendQueryParameter("xoauth_display_name", "Android Device")
                .appendQueryParameter("lang", locale.getLanguage())
                .appendQueryParameter("cc", locale.getCountry().toLowerCase(Locale.US))
                .appendQueryParameter("langCountry", locale.toString().toLowerCase(Locale.US))
                .appendQueryParameter("hl", locale.toString().replace("_", "-"))
                .appendQueryParameter("tmpl", tmpl)
                .build().toString();
    }

    private class JsBridge {

        @JavascriptInterface
        public final void addAccount(String json) {
            Log.d(TAG, "JSBridge: addAccount: " + json);
        }

        @JavascriptInterface
        public final void attemptLogin(String accountName, String password) {
            Log.d(TAG, "JSBridge: attemptLogin: " + accountName + ", " + password);
        }

        @JavascriptInterface
        public void backupSyncOptIn(String accountName) {
            Log.d(TAG, "JSBridge: backupSyncOptIn: " + accountName);
        }

        @JavascriptInterface
        public final void cancelFido2SignRequest() {
            Log.d(TAG, "JSBridge: cancelFido2SignRequest");
//            fidoHandler.cancel();
        }

        @JavascriptInterface
        public void clearOldLoginAttempts() {
            Log.d(TAG, "JSBridge: clearOldLoginAttempts");
        }

        @JavascriptInterface
        public final void closeView() {
            Log.d(TAG, "JSBridge: closeView");
            closeWeb(false);
        }

        @JavascriptInterface
        public void fetchIIDToken(String entity) {
            Log.d(TAG, "JSBridge: fetchIIDToken: " + entity);
        }

        @JavascriptInterface
        public final String fetchVerifiedPhoneNumber() {
            Log.d(TAG, "JSBridge: fetchVerifiedPhoneNumber");
            return null;
        }

        @SuppressWarnings("MissingPermission")
        @JavascriptInterface
        public final String getAccounts() {
            Log.d(TAG, "JSBridge: getAccounts");
            JSONArray json = new JSONArray();
            return json.toString();
        }

        @JavascriptInterface
        public final String getAllowedDomains() {
            Log.d(TAG, "JSBridge: getAllowedDomains");
            return new JSONArray().toString();
        }

        @JavascriptInterface
        public final String getAndroidId() {
            long androidId = LastCheckinInfo.read(LoginActivity.this).getAndroidId();
            Log.d(TAG, "JSBridge: getAndroidId");
            if (androidId == 0 || androidId == -1) return null;
            return Long.toHexString(androidId);
        }

        @JavascriptInterface
        public final int getAuthModuleVersionCode() {
            return GMS_VERSION_CODE;
        }

        @JavascriptInterface
        public final int getBuildVersionSdk() {
            return Build.VERSION.SDK_INT;
        }

        @JavascriptInterface
        public int getDeviceContactsCount() {
            return -1;
        }

        @JavascriptInterface
        public final int getDeviceDataVersionInfo() {
            return 1;
        }

        @JavascriptInterface
        public final void getDroidGuardResult(String s) {
            Log.d(TAG, "JSBridge: getDroidGuardResult: " + s);
//            try {
//                JSONArray array = new JSONArray(s);
//                StringBuilder sb = new StringBuilder();
//                sb.append(getAndroidId()).append(":").append(getBuildVersionSdk()).append(":").append(getPlayServicesVersionCode());
//                for (int i = 0; i < array.length(); i++) {
//                    sb.append(":").append(array.getString(i));
//                }
//                String dg = Base64.encodeToString(MessageDigest.getInstance("SHA1").digest(sb.toString().getBytes()), 0);
//                dgHandler.start(dg);
//            } catch (Exception e) {
//                // Ignore
//            }
        }

        @JavascriptInterface
        public final String getFactoryResetChallenges() {
            return new JSONArray().toString();
        }

        @JavascriptInterface
        public final String getPhoneNumber() {
            return null;
        }

        @JavascriptInterface
        public final int getPlayServicesVersionCode() {
            return GMS_VERSION_CODE;
        }

        @JavascriptInterface
        public final String getSimSerial() {
            return null;
        }

        @JavascriptInterface
        public final int getSimState() {
            return SIM_STATE_UNKNOWN;
        }

        @JavascriptInterface
        public final void goBack() {
            Log.d(TAG, "JSBridge: goBack");
        }

        @JavascriptInterface
        public final boolean hasPhoneNumber() {
            return false;
        }

        @JavascriptInterface
        public final boolean hasTelephony() {
            return false;
        }

        @JavascriptInterface
        public final void hideKeyboard() {
            inputMethodManager.hideSoftInputFromWindow(webView.getWindowToken(), 0);
        }

        @JavascriptInterface
        public final boolean isUserOwner() {
            return true;
        }

        @JavascriptInterface
        public final void launchEmergencyDialer() {
            Log.d(TAG, "JSBridge: launchEmergencyDialer");
        }

        @JavascriptInterface
        public final void log(String s) {
            Log.d(TAG, "JSBridge: log: " + s);
        }

        @JavascriptInterface
        public final void notifyOnTermsOfServiceAccepted() {
            Log.d(TAG, "JSBridge: notifyOnTermsOfServiceAccepted");
        }

        @JavascriptInterface
        public final void sendFido2SkUiEvent(String event) {
            Log.d(TAG, "JSBridge: sendFido2SkUiEvent: " + event);
//            fidoHandler.onEvent(event);
        }

        @JavascriptInterface
        public final void setAccountIdentifier(String accountName) {
            Log.d(TAG, "JSBridge: setAccountIdentifier: " + accountName);
        }

        @JavascriptInterface
        public void setAllActionsEnabled(boolean z) {
            Log.d(TAG, "JSBridge: setAllActionsEnabled: " + z);
        }

        @TargetApi(HONEYCOMB)
        @JavascriptInterface
        public final void setBackButtonEnabled(boolean backButtonEnabled) {
            if (SDK_INT <= GINGERBREAD_MR1) return;
            int visibility = getWindow().getDecorView().getSystemUiVisibility();
            if (backButtonEnabled)
                visibility &= -STATUS_BAR_DISABLE_BACK;
            else
                visibility |= STATUS_BAR_DISABLE_BACK;
            getWindow().getDecorView().setSystemUiVisibility(visibility);
        }


        @JavascriptInterface
        public final void setNewAccountCreated() {
            Log.d(TAG, "JSBridge: setNewAccountCreated");
        }

        @JavascriptInterface
        public void setPrimaryActionEnabled(boolean z) {
            Log.d(TAG, "JSBridge: setPrimaryActionEnabled: " + z);
        }

        @JavascriptInterface
        public void setPrimaryActionLabel(String str, int i) {
            Log.d(TAG, "JSBridge: setPrimaryActionLabel: " + str);
        }

        @JavascriptInterface
        public void setSecondaryActionEnabled(boolean z) {
            Log.d(TAG, "JSBridge: setSecondaryActionEnabled: " + z);
        }

        @JavascriptInterface
        public void setSecondaryActionLabel(String str, int i) {
            Log.d(TAG, "JSBridge: setSecondaryActionLabel: " + str);
        }

        @JavascriptInterface
        public final void showKeyboard() {
            inputMethodManager.showSoftInput(webView, SHOW_IMPLICIT);
        }

        @JavascriptInterface
        public final void showView() {
            runOnUiThread(() -> webView.setVisibility(VISIBLE));
        }

        @JavascriptInterface
        public final void skipLogin() {
            Log.d(TAG, "JSBridge: skipLogin");
            finish();
        }

        @JavascriptInterface
        public final void startAfw() {
            Log.d(TAG, "JSBridge: startAfw");
        }

        @JavascriptInterface
        public final void startFido2SignRequest(String request) {
            Log.d(TAG, "JSBridge: startFido2SignRequest: " + request);
//            fidoHandler.startSignRequest(request);
        }

    }
}
