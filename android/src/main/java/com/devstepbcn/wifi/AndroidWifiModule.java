package com.devstepbcn.wifi;

import com.facebook.react.uimanager.*;
import com.facebook.react.bridge.*;
import com.facebook.systrace.Systrace;
import com.facebook.systrace.SystraceMessage;
import com.facebook.react.LifecycleState;
import com.facebook.react.ReactInstanceManager;
import com.facebook.react.ReactRootView;
import com.facebook.react.modules.core.DefaultHardwareBackBtnHandler;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.shell.MainReactPackage;
import com.facebook.soloader.SoLoader;

import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.WifiLock;
import android.net.wifi.WifiConfiguration;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiInfo;
import android.os.Build;
import android.content.Context;
import android.text.TextUtils;

import android.util.Log;
import java.util.List;
import java.lang.Thread;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class AndroidWifiModule extends ReactContextBaseJavaModule {

    public static final String LOG_TAG = "MyFlair";

    //WifiManager Instance
    WifiManager wifi;
    WifiLock lock;
    ConnectivityManager connectivityManager;

    //Constructor
    public AndroidWifiModule(ReactApplicationContext reactContext) {
        super(reactContext);
        wifi = (WifiManager)reactContext.getSystemService(Context.WIFI_SERVICE);
        connectivityManager = (ConnectivityManager) reactContext.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    //Name for module register to use:
    @Override
    public String getName() {
        return "AndroidWifiModule";
    }

    //Method to load wifi list into string via Callback. Returns a stringified JSONArray
    @ReactMethod
    public void loadWifiList(Callback successCallback, Callback errorCallback) {
        try {
            List < ScanResult > results = wifi.getScanResults();
            JSONArray wifiArray = new JSONArray();

            for (ScanResult result: results) {
                JSONObject wifiObject = new JSONObject();
                if(!result.SSID.equals("")){
                    try {
                        wifiObject.put("SSID", result.SSID);
                        wifiObject.put("BSSID", result.BSSID);
                        wifiObject.put("capabilities", result.capabilities);
                        wifiObject.put("frequency", result.frequency);
                        wifiObject.put("level", result.level);
                        wifiObject.put("timestamp", result.timestamp);
                    } catch (JSONException e) {
                        errorCallback.invoke(e.getMessage());
                    }
                    wifiArray.put(wifiObject);
                }
            }
            successCallback.invoke(wifiArray.toString());
        } catch (IllegalViewOperationException e) {
            errorCallback.invoke(e.getMessage());
        }
    }

    //Method to check if wifi is enabled
    @ReactMethod
    public void isEnabled(Callback isEnabled) {
        isEnabled.invoke(wifi.isWifiEnabled());
    }

    //Method to connect/disconnect wifi service
    @ReactMethod
    public void setEnabled(Boolean enabled) {
        wifi.setWifiEnabled(enabled);
    }

    //Send the ssid and password of a Wifi network into this to connect to the network.
    //Example:  wifi.findAndConnect(ssid, password);
    //After 10 seconds, a post telling you whether you are connected will pop up.
    //Callback returns true if ssid is in the range
    @ReactMethod
    public void findAndConnect(String ssid, String password, Boolean bind, Callback ssidFound) {
        List < ScanResult > results = wifi.getScanResults();
        boolean connected = false;
        for (ScanResult result: results) {
            String resultString = "" + result.SSID;
            if (ssid.equals(resultString)) {
                Log.d(LOG_TAG, "Found WiFi");
                connectTo(result, password, '"' + ssid + '"', bind, ssidFound);
                break;
            }
        }
    }

    //Use this method to check if the device is currently connected to Wifi.
    @ReactMethod
    public void connectionStatus(Callback connectionStatusResult) {
        ConnectivityManager connManager = (ConnectivityManager) getReactApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo mWifi = connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        if (mWifi.isConnected()) {
            connectionStatusResult.invoke(true);
        } else {
            connectionStatusResult.invoke(false);
        }
    }

    //Method to connect to WIFI Network
    public void connectTo(ScanResult result, String password, final String ssid, Boolean bind, final Callback ssidFound) {
        //Make new configuration
        WifiConfiguration conf = new WifiConfiguration();
        conf.SSID = ssid;
        String Capabilities = result.capabilities;
        if (Capabilities.contains("WPA2")) {
            conf.preSharedKey = "\"" + password + "\"";
        } else if (Capabilities.contains("WPA")) {
            conf.preSharedKey = "\"" + password + "\"";
        } else if (Capabilities.contains("WEP")) {
            conf.wepKeys[0] = "\"" + password + "\"";
            conf.wepTxKeyIndex = 0;
            conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
            conf.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
        } else {
            conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
        }
        int networkId = wifi.addNetwork(conf);
        if (networkId != -1) {
            connect(networkId, ssid, bind, ssidFound);
        } else {
            List<WifiConfiguration> mWifiConfigList = wifi.getConfiguredNetworks();
            for( WifiConfiguration i : mWifiConfigList) {
                if(i.SSID != null && i.SSID.equals(ssid)) {
                    connect(i.networkId, ssid, bind, ssidFound);
                    break;
                }
            }
        }
    }

    public void getLock() {
        if (lock == null) {
            lock = wifi.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "MyFlair Lock");
            lock.acquire();
        }
    }

    @ReactMethod
    public void forgetSsid(String ssid, Callback cb) {
        List<WifiConfiguration> mWifiConfigList = wifi.getConfiguredNetworks();
        for( WifiConfiguration i : mWifiConfigList) {
            if(i.SSID != null && i.SSID.equals(ssid)) {
                Log.d(LOG_TAG, "Removing: ");
                boolean succ = wifi.removeNetwork(i.networkId);
                cb.invoke(succ);
                break;
            }
        }
        cb.invoke(false);
    }

    public void emitBindingEvent(String event) {
        WritableMap map = Arguments.createMap();
        map.putString("event", event);
        getReactApplicationContext()
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
            .emit("binding-event", map);
    }

    @ReactMethod
    public void bind(final String ssid, final Callback ssidFound) {
        getLock();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            NetworkRequest.Builder builder = new NetworkRequest.Builder();
            builder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
            connectivityManager.requestNetwork(builder.build(), new ConnectivityManager.NetworkCallback() {
                    private AndroidWifiModule parent;
                    private boolean bound = false;
                    @Override
                    public void onAvailable(Network network) {
                        NetworkInfo networkInfo = connectivityManager.getNetworkInfo(network);
                        if (TextUtils.equals(networkInfo.getExtraInfo(), ssid) && !bound) {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                Log.d(LOG_TAG, "Bound 2: " + networkInfo.getExtraInfo());
                                connectivityManager.bindProcessToNetwork(network);
                            } else {
                                ConnectivityManager.setProcessDefaultNetwork(network);
                            }
                            try {
                                bound = true;
                                parent.emitBindingEvent("bound");
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                    public void onLost(Network network) {
                        if (bound) {
                            connectivityManager.unregisterNetworkCallback(this);
                            Log.d(LOG_TAG, "UnBound 2");
                            bound = false;
                            parent.unbind();
                            parent.emitBindingEvent("disconnected");
                        }
                    }
                    public ConnectivityManager.NetworkCallback init(AndroidWifiModule parent) {
                        this.parent = parent;
                        return this;
                    }
                }.init(this));
        }
    }

    public void connect(int networkId, final String ssid, Boolean bind, final Callback ssidFound) {
        getLock();

        boolean disconnect = wifi.disconnect();
        if ( !disconnect ) {
            Log.d(LOG_TAG, "Failed to disconnect");
            ssidFound.invoke("disconnect-failed");
        };

        if (bind) {
            bind(ssid, ssidFound);
        }

        boolean enableNetwork = wifi.enableNetwork(networkId, true);
        if ( !enableNetwork ) {
            Log.d(LOG_TAG, "Failed to enable");
            ssidFound.invoke("enable-failed");
        };

        if (!bind) {
            ssidFound.invoke("finished");
        }
    }

    //Disconnect current Wifi.
    @ReactMethod
    public void disconnect() {
        wifi.disconnect();
        unbind();
    }

    @ReactMethod
    public void unbind() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            connectivityManager.bindProcessToNetwork(null);
        } else {
            ConnectivityManager.setProcessDefaultNetwork(null);
        }
        if (lock != null) {
            lock.release();
            lock = null;
        }
    }

    //This method will return current ssid
    @ReactMethod
    public void getSSID(final Callback callback) {
        WifiInfo info = wifi.getConnectionInfo();

        // This value should be wrapped in double quotes, so we need to unwrap it.
        String ssid = info.getSSID();
        if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
            ssid = ssid.substring(1, ssid.length() - 1);
        }

        callback.invoke(ssid);
    }

    //This method will return the basic service set identifier (BSSID) of the current access point
    @ReactMethod
    public void getBSSID(final Callback callback) {
        WifiInfo info = wifi.getConnectionInfo();

        String bssid = info.getBSSID();

        callback.invoke(bssid.toUpperCase());
    }

    //This method will return current wifi signal strength
    @ReactMethod
    public void getCurrentSignalStrength(final Callback callback) {
        int linkSpeed = wifi.getConnectionInfo().getRssi();
        callback.invoke(linkSpeed);
    }
    //This method will return current IP
    @ReactMethod
    public void getIP(final Callback callback) {
        WifiInfo info = wifi.getConnectionInfo();
        String stringip=longToIP(info.getIpAddress());
        callback.invoke(stringip);
    }

    public static String longToIP(int longIp){
        StringBuffer sb = new StringBuffer("");
        String[] strip=new String[4];
        strip[3]=String.valueOf((longIp >>> 24));
        strip[2]=String.valueOf((longIp & 0x00FFFFFF) >>> 16);
        strip[1]=String.valueOf((longIp & 0x0000FFFF) >>> 8);
        strip[0]=String.valueOf((longIp & 0x000000FF));
        sb.append(strip[0]);
        sb.append(".");
        sb.append(strip[1]);
        sb.append(".");
        sb.append(strip[2]);
        sb.append(".");
        sb.append(strip[3]);
        return sb.toString();
    }
}

