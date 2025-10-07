/*
** Copyright 2015, Mohamed Naufal
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

package xyz.hexene.localvpn;

import static android.system.OsConstants.IPPROTO_TCP;
import static android.system.OsConstants.IPPROTO_UDP;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.res.Resources;
import android.net.ConnectivityManager;
import android.content.pm.PackageManager;

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
//import android.support.v4.content.LocalBroadcastManager;

import androidx.core.app.NotificationCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import android.util.Log;
import android.view.WindowManager;


import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.io.IOException;

import java.net.InetSocketAddress;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.Selector;

import java.util.HashMap;

import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import androidx.fragment.app.DialogFragment;


public class LocalVPNService extends VpnService
{
    static LinkedList<String> blockedApplications = new LinkedList<String>();
    static LinkedList<String> allowedApplications = new LinkedList<String>();
    private static final String TAG = LocalVPNService.class.getSimpleName();
    private static final String VPN_ADDRESS = "10.0.0.2"; // Only IPv4 support for now
    private static final String VPN_ROUTE = "0.0.0.0"; // Intercept everything

    public static final String BROADCAST_VPN_STATE = "xyz.hexene.localvpn.VPN_STATE";
    private static final String CHANNEL_ID = "LocalVPNChannelID";

    private static boolean isRunning = false;

    private ParcelFileDescriptor vpnInterface = null;

    private PendingIntent pendingIntent;

    private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
    private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;
    private ExecutorService executorService;

    private Selector udpSelector;
    private Selector tcpSelector;

    @Override
    public void onCreate()
    {
        super.onCreate();
        isRunning = true;

        createNotificationChannel();

        setupVPN();
        try
        {
            udpSelector = Selector.open();
            tcpSelector = Selector.open();
            deviceToNetworkUDPQueue = new ConcurrentLinkedQueue<>();
            deviceToNetworkTCPQueue = new ConcurrentLinkedQueue<>();
            networkToDeviceQueue = new ConcurrentLinkedQueue<>();

            executorService = Executors.newFixedThreadPool(5);
            executorService.submit(new UDPInput(networkToDeviceQueue, udpSelector));
            executorService.submit(new UDPOutput(deviceToNetworkUDPQueue, udpSelector, this));
            executorService.submit(new TCPInput(networkToDeviceQueue, tcpSelector));
            executorService.submit(new TCPOutput(deviceToNetworkTCPQueue, networkToDeviceQueue, tcpSelector, this));
            executorService.submit(new VPNRunnable(vpnInterface.getFileDescriptor(),
                    deviceToNetworkUDPQueue, deviceToNetworkTCPQueue, networkToDeviceQueue));
            LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(BROADCAST_VPN_STATE).putExtra("running", true));
            Log.i(TAG, "Started");
        }
        catch (IOException e)
        {
            // TODO: Here and elsewhere, we should explicitly notify the user of any errors
            // and suggest that they stop the service, since we can't do it ourselves
            Log.e(TAG, "Error starting service", e);
            cleanup();
        }
    }

    private void setupVPN()
    {
        if (vpnInterface == null)
        {
            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, 32);
            //builder.addRoute(VPN_ROUTE, 0); Used when I want to intercept all traffic through the VPN tunnel

            //Intercepting only traffic that has a destination address that is part of the private IPs range
            //10.0.0.0 – 10.255.255.255, 172.16.0.0 – 172.31.255.255, 192.168.0.0 – 192.168.255.255
            builder.addRoute("10.0.0.0", 8);
            builder.addRoute("172.16.0.0", 12);
            builder.addRoute("192.168.0.0", 16);

            vpnInterface = builder.setSession(getString(R.string.app_name)).setConfigureIntent(pendingIntent).establish();
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
        return START_STICKY;
    }

    public static boolean isRunning()
    {
        return isRunning;
    }

    @Override
    public void onDestroy()
    {
        super.onDestroy();
        isRunning = false;
        executorService.shutdownNow();
        cleanup();
        Log.i(TAG, "Stopped");
    }

    @SuppressLint("NewApi")
    private void cleanup()
    {
        deviceToNetworkTCPQueue = null;
        deviceToNetworkUDPQueue = null;
        networkToDeviceQueue = null;
        ByteBufferPool.clear();
        closeResources(udpSelector, tcpSelector, vpnInterface);
    }

    // TODO: Move this to a "utils" class for reuse
    private static void closeResources(Closeable... resources)
    {
        for (Closeable resource : resources)
        {
            try
            {
                resource.close();
            }
            catch (IOException e)
            {
                // Ignore
            }
        }
    }

    //Method necessary for displaying notifications now, each notification type ot group needs to be assigned to a notification
    //channel
    private void createNotificationChannel() {
        // Create the NotificationChannel, but only on API 26+ because
        // the NotificationChannel class is not in the Support Library.
        Log.d("Notification", "Building the notification channel");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = getString(R.string.channel_name);
            String description = getString(R.string.channel_description);
            int importance = NotificationManager.IMPORTANCE_HIGH;
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);

            // Register the channel with the system. You can't change the importance
            // or other notification behaviors after this.
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }

    //Method for displaying a notification on Android screen
    //Argument: packageName. The string represents the application's package name
    private void SendNotification(String appName, String packageName){

        //createNotificationChannel();

        Intent allowIntent = new Intent(this, NotificationActionReceiver.class);
        allowIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        allowIntent.setAction("actionAllow");
        allowIntent.putExtra("packageName", packageName);
        PendingIntent allowPendingIntent = PendingIntent.getBroadcast(this, 123,allowIntent,PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent blockIntent = new Intent(this, NotificationActionReceiver.class);
        blockIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        blockIntent.setAction("actionBlock");
        blockIntent.putExtra("packageName", packageName);
        PendingIntent blockPendingIntent = PendingIntent.getBroadcast(this, 124,blockIntent,PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);


        NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID);

        builder.setSmallIcon(R.drawable.notification_icon);
        builder.setContentTitle("Local VPN Alert");
        builder.setContentText("Application " + appName + " is trying to access the local network");
        builder.setPriority(NotificationCompat.PRIORITY_HIGH);

        builder.addAction(R.drawable.allow_icon, "Allow", allowPendingIntent);
        builder.addAction(R.drawable.block_icon, "Block", blockPendingIntent);

        //create and display notification. The notification's unique code is 123
        notificationManager.notify(123, builder.build());

    }

    public static class NotificationActionReceiver extends BroadcastReceiver{
        @Override
        public void onReceive(Context context, Intent intent) {

            Log.d("Receiver", "ON RECEIVER");
            String action = intent.getAction();
            NotificationManager notifyManager= (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

            if (action.equals("actionAllow")){

                Log.d("Receiver", "I AM ON ALLOW RECEIVER" + intent.getExtras().getString("packageName"));
                allowedApplications.add(intent.getExtras().getString("packageName"));

                //when action Allow is pressed then the notification goes away
                notifyManager.cancel(123);

                //changes: Here code after allowing traffic, do nothing actually OR block these apps from being
                // monitored from the VPN tunnel

                //Intent wakeIntent = new Intent(context.getApplicationContext(), DialogDisplay.class);
                //wakeIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                //context.getApplicationContext().startActivity(wakeIntent);
            }
            if (action.equals("actionBlock")){
                Log.d("Receiver", "ON BLOCK RECEIVER");

                blockedApplications.add(intent.getExtras().getString("packageName"));


                //when action Block is pressed notification goes away
                notifyManager.cancel(123);

                //changes: Here goes code to block access
            }
        }
    }

    private class VPNRunnable implements Runnable
    {
        ConnectivityManager connectivitymanager = (ConnectivityManager)getSystemService(Context.CONNECTIVITY_SERVICE);
        //PackageManager packageManager = Context.getPackageManager();

        PackageManager packageManager = getPackageManager();
        private final String TAG = VPNRunnable.class.getSimpleName();

        private FileDescriptor vpnFileDescriptor;

        private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
        private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
        private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;

        public VPNRunnable(FileDescriptor vpnFileDescriptor,
                           ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue,
                           ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue,
                           ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue)
        {
            this.vpnFileDescriptor = vpnFileDescriptor;
            this.deviceToNetworkUDPQueue = deviceToNetworkUDPQueue;
            this.deviceToNetworkTCPQueue = deviceToNetworkTCPQueue;
            this.networkToDeviceQueue = networkToDeviceQueue;
        }

        @SuppressLint("NewApi")
        @Override
        public void run()
        {
            Log.i(TAG, "Started");

            int uid;
            int isSamePort = 0;
            //List<Integer> ownerUIDs = new ArrayList<Integer>();

            Map<Integer, String> uidToNameMap = new HashMap<Integer, String>();

            String packageName;
            String appName = null;

            FileChannel vpnInput = new FileInputStream(vpnFileDescriptor).getChannel();
            FileChannel vpnOutput = new FileOutputStream(vpnFileDescriptor).getChannel();

            try
            {
                ByteBuffer bufferToNetwork = null;
                boolean dataSent = true;
                boolean dataReceived;
                while (!Thread.interrupted())
                {
                    if (dataSent)
                        bufferToNetwork = ByteBufferPool.acquire();
                    else
                        bufferToNetwork.clear();

                    // TODO: Block when not connected
                    int readBytes = vpnInput.read(bufferToNetwork);
                    if (readBytes > 0)
                    {
                        dataSent = true;
                        bufferToNetwork.flip();
                        Packet packet = new Packet(bufferToNetwork);
                        if (packet.isUDP())
                        {
                            //User ID is necessary to get to the application's name. It's the unique identifier that gets assigned to an app
                            //when it gets installed
                            uid = connectivitymanager.getConnectionOwnerUid (IPPROTO_UDP,new InetSocketAddress(packet.ip4Header.sourceAddress.getHostAddress(), packet.udpHeader.sourcePort), new InetSocketAddress(packet.ip4Header.destinationAddress.getHostAddress(), packet.udpHeader.destinationPort));

                            packageName = packageManager.getNameForUid(uid);

                            if(!uidToNameMap.containsKey(uid) && packageManager.getNameForUid(uid) != null){
                                Log.w("Conne", "Im inside the if statement");
                                //ownerUIDs.add(uid);


                                //keep a map with the pairs of UID and the package name of the application sending traffic
                                uidToNameMap.put(uid, packageName);
                                ApplicationInfo applicationInfo = packageManager.getApplicationInfo(packageName, 0);

                                Resources resources = packageManager.getResourcesForApplication(packageName);
                                appName = resources.getString(applicationInfo.labelRes);

                                Log.d("APP NAME", "APP NAME: "+ appName);

                                //Display a notification when an app tries to access the Local Network
                                SendNotification(appName, packageName);

                                //Log.w("Connection","UIDS: " + Integer.toString(uid) + " Package name" + packageName);
                                //Log.w("connection", "ATTENTION!: " + packageName + " tries to access local network");

                            }


                            //Log.d("BlockedListUDPSide", "BlockedListUDPSide: " + blockedApplications.toString());

                            Log.d("AllowListUDPSide", "ALLOWListUDPSide: " + allowedApplications.toString());

                            //if the package name aka app is not blocked by user forward packets
                            if(allowedApplications.contains(packageName)){
                                Log.d("AllowedListUDPSide", "I AM INSIDE THE IF STATEMENT FOR ALLOW");
                                deviceToNetworkUDPQueue.offer(packet);
                            }
                            //deviceToNetworkUDPQueue.offer(packet);

                            //discuss: I suppose this is where the packet is forward  to the internet so if i work
                            // with this i can choose what to be forwarded and what not
                            //Log.w("Ip packets", "\n\nIPV4 UDP PACKET:   " + packet.ip4Header.destinationAddress.getHostAddress() + "\n\n");


                        }
                        else if (packet.isTCP())
                        {
                            uid = connectivitymanager.getConnectionOwnerUid (IPPROTO_TCP,new InetSocketAddress(packet.ip4Header.sourceAddress.getHostAddress(), packet.tcpHeader.sourcePort), new InetSocketAddress(packet.ip4Header.destinationAddress.getHostAddress(), packet.tcpHeader.destinationPort));

                            packageName = packageManager.getNameForUid(uid);
                            //i hold all the uids-names of the apps that send traffic
                            if(!uidToNameMap.containsKey(uid) && packageManager.getNameForUid(uid) != null){
                                //Log.w("Conne", "Im inside the if statement");
                                //ownerUIDs.add(uid);


                                uidToNameMap.put(uid, packageName);

                                ApplicationInfo applicationInfo = packageManager.getApplicationInfo(packageName, 0);

                                Resources resources = packageManager.getResourcesForApplication(packageName);
                                appName = resources.getString(applicationInfo.labelRes);

                                Log.d("APP NAME", "APP NAME: "+ appName);

                                //String finalPackageName = packageName;

                                SendNotification(appName, packageName);
                                //Log.w("connection", "ATTENTION!: " + packageName + " tries to access local network");

                            }
                            //Log.w("Ip packets", "\n\nIPV4 TCP PACKET:   " + packet.ip4Header.destinationAddress.getHostAddress() + "\n\n");

                            //Log.d("BlockedListTCP", blockedApplications.toString());
                            Log.i("Allowlist", "Allow: " + allowedApplications.toString());

                            //if package name aka app is not blocked from user then forward packet
                            if(allowedApplications.contains(packageName)){
                                Log.i("AllowedListTCPSide", "I AM INSIDE THE IF STATEMENT FOR ALLOW");
                                deviceToNetworkTCPQueue.offer(packet);
                            }
                            //deviceToNetworkTCPQueue.offer(packet);
                        }
                        else
                        {
                            Log.w(TAG, "Unknown packet type");
                            Log.w(TAG, packet.ip4Header.toString());
                            dataSent = false;
                        }
                    }
                    else
                    {
                        dataSent = false;
                    }

                    ByteBuffer bufferFromNetwork = networkToDeviceQueue.poll();
                    if (bufferFromNetwork != null)
                    {
                        bufferFromNetwork.flip();
                        while (bufferFromNetwork.hasRemaining())
                            vpnOutput.write(bufferFromNetwork);
                        dataReceived = true;

                        ByteBufferPool.release(bufferFromNetwork);
                    }
                    else
                    {
                        dataReceived = false;
                    }

                    // TODO: Sleep-looping is not very battery-friendly, consider blocking instead
                    // Confirm if throughput with ConcurrentQueue is really higher compared to BlockingQueue
                    if (!dataSent && !dataReceived)
                        Thread.sleep(10);
                }
            }
            catch (InterruptedException e)
            {
                Log.i(TAG, "Stopping");
            }
            catch (IOException e)
            {
                Log.w(TAG, e.toString(), e);
            } catch (PackageManager.NameNotFoundException e) {
                throw new RuntimeException(e);
            } finally
            {
                closeResources(vpnInput, vpnOutput);
            }
        }
    }
}
