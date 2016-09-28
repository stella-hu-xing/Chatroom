package activitystreamer.server;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.EncryptionUtil;
import activitystreamer.util.Settings;

public class ControlSolution extends Control {

	public class ServerContent {

		String id;
		int load;
		int serverload;
		String hostname;
		int port;

		public ServerContent() {
		}

		public ServerContent(String id, int clientload, int serverload, String hostname, int port) {
			this.id = id;
			this.load = clientload;
			this.serverload = serverload;
			this.hostname = hostname;
			this.port = port;
		}
	}

	//////

	private static final Logger log = LogManager.getLogger();

	private static Hashtable<String, String> AllUserList;
	private static ArrayList<Connection> AnonymousClients;
	private static Hashtable<String, Connection> CurrentClients;

	private static ArrayList<Connection> CurrentServers;
	private static ArrayList<ServerContent> AllOtherServers;

	private Hashtable<Connection, PublicKey> KeyList;

	private JSONParser parser = new JSONParser();
	// the secret for all server network
	private String SSecret;
	private String ID;

	public String backuphost;
	public int backupport;

	private Connection parentCon;

	private ArrayList<String> waitingClient;
	private int counter, counter1;
	private boolean lockis = true;

	private KeyPair keys;
	private PrivateKey ownPrivateKey;
	private PublicKey ownPublicKey;

	private static Hashtable<Connection, Boolean> isNew;

	// since control and its subclasses are singleton, we get the singleton this
	// way
	public static ControlSolution getInstance() {
		if (control == null) {
			control = new ControlSolution();

		}
		return (ControlSolution) control;
	}

	public ControlSolution() {
		super();

		// check if we should initiate a connection and do so if necessary

		if (Settings.getRemoteHostname() == null) {
			SSecret = Settings.nextSecret();

			Settings.setSecret(SSecret);
			log.info("this server network secret is: " + SSecret);
		}

		ID = Settings.nextSecret();
		log.info("this server's id is: " + ID);

		AllUserList = new Hashtable<String, String>();
		CurrentClients = new Hashtable<String, Connection>();
		AllOtherServers = new ArrayList<ServerContent>();
		AnonymousClients = new ArrayList<Connection>();
		CurrentServers = new ArrayList<Connection>();
		waitingClient = new ArrayList<String>();
		KeyList = new Hashtable<Connection, PublicKey>();
		isNew = new Hashtable<Connection, Boolean>();

		keys = EncryptionUtil.generateKey();
		ownPublicKey = keys.getPublic();
		ownPrivateKey = keys.getPrivate();

		initiateConnection();

		backuphost = new String("localhost");
		backupport = 3780;

		start();
	}

	/*
	 * a new incoming connection
	 */
	@Override
	public Connection incomingConnection(Socket s) throws IOException {
		Connection con = super.incomingConnection(s);

		isNew.put(con, false);
		System.out.println("I receive a incomming connection");

		return con;
	}

	/*
	 * a new outgoing connection
	 */
	@Override
	public Connection outgoingConnection(Socket s) throws IOException {
		Connection con = super.outgoingConnection(s);

		isNew.put(con, true);
		sendPublicKey(con);

		CurrentServers.add(con);
		parentCon = con;

		return con;
	}

	/*
	 * the connection has been closed
	 */
	@Override
	public void connectionClosed(Connection con) {
		super.connectionClosed(con);
		// for server
		if (CurrentServers.contains(con)) {
			CurrentServers.remove(con);
		}
		// for client
		Logout(con);
	}

	/*
	 * process incoming msg, from connection con return true if the connection
	 * should be closed, false otherwise
	 */
	@Override
	public synchronized boolean process(Connection con, String msg) {

		// cut the String into command + username +content

		if (isNew.get(con).equals(false)) {
			try {
				JSONObject obj = (JSONObject) parser.parse(msg);
				if (obj.containsKey("command") && obj.get("command").equals("REQUEST_PUBKEY")) {
					isNew.put(con, true);
					System.out.println("A new server/ client！！");
					ReceivepubKey(con, obj);
					answerPublicKey(con);
					// } else if (obj.containsKey("command") &&
					// obj.get("command").equals("ANSWER_PUBKEY")) {
					// ReceivepubKey(con, obj);
					// isNew.put(con, true);
					// sendAuthenticateMsg(con,SSecret);
				} else {
					System.out.println("A old server/ client ！！");
					dealWithCommand(con, obj);
				}
			} catch (ParseException e) {
				e.printStackTrace();
			}
		} else {
			System.out.println("You are HERE！！");

			try {
				System.out.println("Read:   " + msg);
				msg = EncryptionUtil.decyrpt(msg, ownPrivateKey).toString().trim();
				// msg= msg.trim();
				System.out.println("Read again:   " + msg);
				JSONObject obj = (JSONObject) parser.parse(msg);

				dealWithCommand(con, obj);

			} catch (ParseException e) {

				e.printStackTrace();
			}

		}

		return false;

	}

	//
	public void dealWithCommand(Connection con, JSONObject obj) throws ParseException {

		System.out.println("Begin process----");
		String coms = (String) obj.get("command");

		switch (coms) {
		case "ANSWER_PUBKEY":
			ReceivepubKey(con, obj);
			isNew.put(con, true);
			sendAuthenticateMsg(con, Settings.getSecret());

			break;

		case "AUTHENTICATE":

			ReceiveAuthenticate(con, obj);
			break;

		case "AUTHENTICATE_SUCCESS":
			ReceiveAuthenSuccess(con, obj);
			break;

		case "LOGIN":

			Login(con, obj);
			break;

		case "REDIRECT":

			DoRedirect(con, obj);
			break;

		case "LOGOUT":

			Logout(con);
			break;

		case "ACTIVITY_MESSAGE":

			ReceiveActivityMessage(con, obj);
			break;

		case "SERVER_ANNOUNCE":

			ReceiveServerAnnounce(con, obj);
			break;

		case "ACTIVITY_BROADCAST":

			ReceiveActivityBroadCast(con, obj);
			break;

		case "REGISTER":
			Register(con, obj);
			break;

		case "LOCK_REQUEST":

			ReceiveLockRequest(obj);
			break;

		case "LOCK_DENIED":

			ReceiveLockDenied(obj);
			break;

		case "LOCK_ALLOWED":

			ReceiveLockAllowed(obj);
			break;
		default:
			sendMessage(con, "INVALID_MESSAGE", "You send a invalid message");
			break;
		}
	}

	// at the first stage, receive pubkey from client( or server)
	private void ReceivepubKey(Connection con, JSONObject obj) {

		String key = (String) obj.get("publickey");

		byte[] publicBytes = Base64.getDecoder().decode(key);

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);

		KeyFactory keyFactory;

		try {
			keyFactory = KeyFactory.getInstance("RSA");

			PublicKey pubKey = keyFactory.generatePublic(keySpec);

			KeyList.put(con, pubKey);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	// send my Public key to another server or back to client
	private void answerPublicKey(Connection con) {

		String encodedKey = Base64.getEncoder().encodeToString(ownPublicKey.getEncoded());

		JSONObject obj = new JSONObject();

		obj.put("command", "ANSWER_PUBKEY");

		obj.put("publickey", encodedKey);

		con.writeMsg(EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(con)).toString());

	}

	private void sendPublicKey(Connection con) {

		String encodedKey = Base64.getEncoder().encodeToString(ownPublicKey.getEncoded());

		JSONObject obj = new JSONObject();
		obj.put("command", "REQUEST_PUBKEY");
		obj.put("publickey", encodedKey);

		// con.writeMsg(EncryptionUtil.encyrpt(obj.toJSONString(),
		// KeyList.get(con)).toString());
		con.writeMsg(obj.toJSONString());
	}

	private void sendAuthenticateMsg(Connection con, String secret) {
		// TODO Auto-generated method stub
		JSONObject obj = new JSONObject();
		obj.put("command", "AUTHENTICATE");
		obj.put("secret", secret);

		// con.writeMsg(obj.toJSONString());
		con.writeMsg(EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(con)).toString());
	}

	private void ReceiveLockDenied(JSONObject obj) {

		if (obj.get("username") != null && obj.get("secret") != null) {
			System.out.println("Receive Lock Denide for " + obj.get("username") + " :" + obj.get("secret"));
			// receive the message is from my request
			if (waitingClient.contains(obj.get("username"))) {
				counter++;
				lockis = false;
				AllUserList.remove(obj.get("username"), obj.get("secret"));
				waitingClient.remove(obj.get("username"));
			} else {
				// receive the message if from other servers' request
				if (AllUserList.containsKey((String) obj.get("username"))) {
					AllUserList.remove(obj.get("username"), obj.get("secret"));
				}
			}

		}
	}

	private void ReceiveLockAllowed(JSONObject obj) {
		if (obj.get("username") != null && obj.get("secret") != null) {
			System.out.println("Receive Lock Allowed for " + obj.get("username") + " :" + obj.get("secret"));
			// receive the message is from my request
			if (waitingClient.contains(obj.get("username"))) {
				counter1++;
				lockis = true;
			}
		}
	}

	/*
	 * the method to deal with received lock request and return the usename
	 * exists or not
	 */
	private void ReceiveLockRequest(JSONObject obj) {

		// check the <username, secret> is already locked

		// using array to store waiting client ' username and connection

		if (obj.get("username") != null && obj.get("secret") != null) {
			System.out.println("Receive Lock Request for " + obj.get("username") + " :" + obj.get("secret"));
			if (AllUserList.containsKey(obj.get("username")) || waitingClient.contains(obj.get("username"))) {
				sendLockDenied((String) obj.get("username"), (String) obj.get("secret"));
				log.info("send lock denied for: " + (String) obj.get("username") + (String) obj.get("secret"));
			} else {
				System.out.println("no username or secret");
				AllUserList.put((String) obj.get("username"), (String) obj.get("secret"));
				sendLockAllowed((String) obj.get("username"), (String) obj.get("secret"));
				log.info("send lock allowed for: " + (String) obj.get("username") + (String) obj.get("secret"));
			}
		}
	}

	public void SendLockRequest(String username, String secret) {
		// TODO Auto-generated method stub
		System.out.println("now begin to send lock request");
		waitingClient.add(username);
		// chech self
		// check other servers
		if (CurrentServers.size() != 0) {
			JSONObject obj = new JSONObject();
			obj.put("command", "LOCK_REQUEST");
			obj.put("username", username);
			obj.put("secret", secret);

			for (int i = 0; i < CurrentServers.size(); i++) {
				if (isNew.get(CurrentServers.get(i)) == false) {
					CurrentServers.get(i).writeMsg(obj.toJSONString());
				} else {
					CurrentServers.get(i).writeMsg(
							EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(CurrentServers.get(i))).toString());
				}

			}
		}
	}

	private void sendLockAllowed(String currentUser, String currentSec) {
		JSONObject obj = new JSONObject();
		obj.put("command", "LOCK_ALLOWED");
		obj.put("username", currentUser);
		obj.put("secret", currentSec);
		obj.put("server", ID);

		for (int i = 0; i < CurrentServers.size(); i++) {
			if (isNew.get(CurrentServers.get(i)) == false) {
				CurrentServers.get(i).writeMsg(obj.toJSONString());
			} else {
				CurrentServers.get(i).writeMsg(
						EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(CurrentServers.get(i))).toString());
			}
		}
	}

	private void sendLockDenied(String currentUser, String currentSec) {
		JSONObject obj = new JSONObject();
		obj.put("command", "LOCK_DENIED");
		obj.put("username", currentUser);
		obj.put("secret", currentSec);
		obj.put("server", ID);

		for (int i = 0; i < CurrentServers.size(); i++) {
			if (isNew.get(CurrentServers.get(i)) == false) {
				CurrentServers.get(i).writeMsg(obj.toJSONString());
			} else {
				CurrentServers.get(i).writeMsg(
						EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(CurrentServers.get(i))).toString());
			}
		}

	}

	/**
	 * deal with the received Activity Message from client and process the
	 * activity object
	 * 
	 * @param con
	 * @param obj
	 */
	private void ReceiveActivityMessage(Connection con, JSONObject obj) {
		// check the valid

		System.out.println("Receive Activity Message from " + obj.get("username") + " :" + obj.get("secret"));
		String username = (String) obj.get("username");
		JSONObject ob = (JSONObject) obj.get("activity");

		sendActivityBroadcastToAll(ob, username);

	}

	/**
	 * send Activity Broadcast to all servers and related clients
	 */
	private void sendActivityBroadcastToAll(JSONObject obj, String username) {
		JSONObject js = new JSONObject();
		obj.put("authenticated_user", username);
		js.put("command", "ACTIVITY_BROADCAST");
		js.put("activity", obj);

		for (int j = 0; j < CurrentServers.size(); j++) {
			if (isNew.get(CurrentServers.get(j)) == false) {
				CurrentServers.get(j).writeMsg(js.toJSONString());
			} else {
				CurrentServers.get(j).writeMsg(
						EncryptionUtil.encyrpt(js.toJSONString(), KeyList.get(CurrentServers.get(j))).toString());
			}

		}

		for (int j = 0; j < AnonymousClients.size(); j++) {
			if (isNew.get(AnonymousClients.get(j)) == false) {
				AnonymousClients.get(j).writeMsg(js.toJSONString());
			} else {
				AnonymousClients.get(j).writeMsg(
						EncryptionUtil.encyrpt(js.toJSONString(), KeyList.get(AnonymousClients.get(j))).toString());
			}

		}

		Iterator iter = CurrentClients.values().iterator();
		while (iter.hasNext()) {

			Connection co = (Connection) iter.next();
			if (isNew.get(co) == false) {
				co.writeMsg(js.toJSONString());
			} else {
				co.writeMsg(EncryptionUtil.encyrpt(js.toJSONString(), KeyList.get(co)).toString());
			}

		}
	}

	/**
	 * send Activity Broadcast to all servers (without sender) and related
	 * clients
	 */
	private void sendActivityBroadcast(Connection co, JSONObject obj) {
		JSONObject js = new JSONObject();
		js.put("command", "ACTIVITY_BROADCAST");
		js.put("activity", obj.get("activity"));

		for (int j = 0; j < CurrentServers.size(); j++) {
			if (!CurrentServers.get(j).equals(co)) {
				if (isNew.get(CurrentServers.get(j)) == false) {
					CurrentServers.get(j).writeMsg(obj.toJSONString());
				} else {
					CurrentServers.get(j).writeMsg(
							EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(CurrentServers.get(j))).toString());
				}
			}

		}
		for (int j = 0; j < AnonymousClients.size(); j++) {
			if (isNew.get(AnonymousClients.get(j)) == false) {
				AnonymousClients.get(j).writeMsg(js.toJSONString());
			} else {
				AnonymousClients.get(j).writeMsg(
						EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(AnonymousClients.get(j))).toString());
			}

		}

		Iterator iter = CurrentClients.values().iterator();
		while (iter.hasNext()) {

			Connection con = (Connection) iter.next();
			if (isNew.get(co) == false) {
				co.writeMsg(js.toJSONString());
			} else {
				co.writeMsg(EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(co)).toString());
			}
		}
	}

	/**
	 * the method to deal with the received activity broadcast
	 * 
	 * @param con
	 * @param obj
	 */
	private void ReceiveActivityBroadCast(Connection con, JSONObject obj) {
		sendActivityBroadcast(con, obj);
	}

	/**
	 * The method to handle received authenticate message
	 * 
	 * @param con
	 * @param obj
	 */
	private void ReceiveAuthenticate(Connection con, JSONObject obj) {

		if (isNew.get(con) == true) {
			int load = CurrentServers.size();
			// this server is not a root server
			if (obj.get("secret").equals(SSecret)) {
				// not redirect
				if (load < 2 || (load >= 2 && checkServerMinload().id == ID)) {
					CurrentServers.add(con);

					// send current alluser list to the new server to make every
					// server
					// in the same page
					sendAuthenSuccess(con);
				} else {
					sendDoRedirectToServer(con);
				}
			} else if (obj.get("secret").equals(Settings.getSecret())) {
				SSecret = Settings.getSecret();
				CurrentServers.add(con);
				sendAuthenSuccess(con);
			} else {

				sendMessage(con, "AUTHENTICATION_FAIL", "the supplied secret is incorrect:" + obj.get("secret"));
				con.closeCon();
			}
		} else {
			if (obj.get("secret").equals(SSecret)) {
				CurrentServers.add(con);
			} else if (obj.get("secret").equals(Settings.getSecret())) {
				SSecret = Settings.getSecret();
				CurrentServers.add(con);
			}
		}

	}

	private void sendDoRedirectToServer(Connection con) {
		// do redirect
		ServerContent sc = checkServerMinload();
		JSONObject o = new JSONObject();
		o.put("command", "REDIRECT");
		o.put("hostname", sc.hostname);
		o.put("port", sc.port);
		if (isNew.get(con) == false) {
			con.writeMsg(o.toJSONString());
		} else {
			con.writeMsg(EncryptionUtil.encyrpt(o.toJSONString(), KeyList.get(con)).toString());
		}
		System.out.println("now to redirect to server!!!");

	}

	private void DoRedirect(Connection con, JSONObject obj) {
		String hn = (String) obj.get("hostname");
		int port = (int) (long) obj.get("port");
		// clientSocket.close();
		connectionClosed(con);
		try {
			outgoingConnection(new Socket(hn, port));
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	// send current alluser list to the new server to make every server in the
	// same page
	private void sendAuthenSuccess(Connection con) {
		JSONObject obj = new JSONObject();
		obj.put("command", "AUTHENTICATE_SUCCESS");
		// send all user list
		JSONObject j = new JSONObject();
		j.putAll(AllUserList);
		obj.put("userlist", j);

		// send back up server
		obj.put("backuphost", backuphost);
		obj.put("backupport", backupport);
		if (isNew.get(con) == false) {
			con.writeMsg(obj.toJSONString());
		} else {
			con.writeMsg(EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(con)).toString());
		}
	}

	/*
	 * receive userlist after send authenticate message
	 */
	private void ReceiveAuthenSuccess(Connection con, JSONObject obj) {

		// update user list
		JSONObject newUserlist = new JSONObject();
		newUserlist = (JSONObject) obj.get("userlist");

		AllUserList.putAll(newUserlist);

		// set up back up host
		backuphost = (String) obj.get("backuphost");
		// backupport = (Integer)obj.get("backupport");
		backupport = Integer.valueOf(((Long) obj.get("backupport")).toString());
	}

	private void sendMessage(Connection con, String command, String info) {

		JSONObject obj = new JSONObject();
		obj.put("command", command);
		obj.put("info", info);

		System.out.println("object is " + obj.toJSONString());
		if (isNew.get(con) == false) {
			con.writeMsg(obj.toJSONString());
		} else {
			con.writeMsg(EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(con)).toString());
		}
	}

	/**
	 * Register Method
	 * 
	 * @param con
	 */
	public void Register(Connection con, JSONObject obj) {

		// firstly, check the obj is valid
		if (obj.get("username") != null && obj.get("secret") != null) {
			String username = (String) obj.get("username");
			String secret = (String) obj.get("secret");
			// check the connections exist or not
			if (!AllUserList.containsKey(username) && !waitingClient.contains(username)) {

				// AllUserList.put(username, secret);
				waitingClient.add(username);
				SendLockRequest(username, secret);

				// waiting for response
				try {
					this.wait(3000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				// chech the lock success or be denied

				if (lockis == true) {
					if ((counter + counter1) == AllOtherServers.size()) {
						// log.info("Register 1 user:" + username);
						waitingClient.remove(username);
						AllUserList.put(username, secret);
						sendMessage(con, "REGISTER_SUCCESS", "register success for " + username);

					} else {
						log.info("Not all server response in time");
						waitingClient.remove(username);
						AllUserList.put(username, secret);
						sendMessage(con, "REGISTER_SUCCESS", "register success for " + username);
					}
				} else {
					waitingClient.remove(username);
					sendMessage(con, "REGISTER_FAILED", "The username or secret you input has already exsited");

				}
			} else
				sendMessage(con, "REGISTER_FAILED", "The username or secret you input has already exsited");

		} else
			sendMessage(con, "REGISTER_FAILED", "The username or secret you input is invalid");

	}

	/**
	 * Login method
	 */

	public void Login(Connection con, JSONObject obj) {
		int load = CurrentClients.size() + AnonymousClients.size();

		// check the anonymous user
		if ((obj.get("username").equals("anonymous") || obj.get("username").equals("Anonymous"))
				&& obj.get("secret") == null) {

			if (load < 2 || (load >= 2 && checkClientMinload().id == ID)) {
				AnonymousClients.add(con);
				sendMessage(con, "LOGIN_SUCCESS", "logged in as anonymous");
			} else {
				// do redirect
				ServerContent sc = checkClientMinload();
				JSONObject o = new JSONObject();
				o.put("command", "REDIRECT");
				o.put("hostname", sc.hostname);
				o.put("port", sc.port);
				if (isNew.get(con) == false) {
					con.writeMsg(o.toJSONString());
				} else {
					con.writeMsg(EncryptionUtil.encyrpt(o.toJSONString(), KeyList.get(con)).toString());
				}
				System.out.println("now to redirect!!!");
			}
		} else {
			// check the message is valid or not
			if (obj.get("username") != null && obj.get("secret") != null) {
				// check the user exist or not
				String usern = (String) obj.get("username");
				String sec = (String) obj.get("secret");
				log.debug("in login: " + usern + "       " + sec);
				// check the user has registered or not
				if (AllUserList.containsKey(usern) && AllUserList.get(usern).equals(sec)) {
					// check the user has alreay logged in or not
					if (!CurrentClients.containsKey(usern)) {
						// check load in order to redirect
						if (load < 2 || (load >= 2 && checkClientMinload().id == ID)) {
							CurrentClients.put(usern, con);
							sendMessage(con, "LOGIN_SUCCESS", "logged in with name " + usern);
							System.out.println("not dirrect=======");
						} else {
							// do redirect
							System.out.println("now to redirect!!!");
							ServerContent sc = checkClientMinload();
							JSONObject o = new JSONObject();
							o.put("command", "REDIRECT");
							o.put("hostname", sc.hostname);
							o.put("port", sc.port);
							if (isNew.get(con) == false) {
								con.writeMsg(o.toJSONString());
							} else {
								con.writeMsg(EncryptionUtil.encyrpt(o.toJSONString(), KeyList.get(con)).toString());
							}
							CurrentClients.remove(usern, con);

						}
					} else {
						sendMessage(con, "LOGIN_FAILED", "user has already logged");
					}

				} else {
					sendMessage(con, "LOGIN_FAILED", "attempt to login with wrong username or secret");
				}

			} else {
				sendMessage(con, "INVALID_MESSAGE", "The username or secret you input is invalid");
			}
		}

	}

	// check there is a server with less load
	private ServerContent checkClientMinload() {
		System.out.println("doing search server with mininum number of load...");

		Iterator iter = AllOtherServers.iterator();

		ServerContent min = new ServerContent(ID, CurrentClients.size() + AnonymousClients.size(),
				CurrentServers.size(), Settings.getLocalHostname(), Settings.getLocalPort());

		while (iter.hasNext()) {
			ServerContent temp = new ServerContent();
			temp = (ServerContent) iter.next();
			log.debug("the current obj is " + temp);
			// if ((temp.load < (CurrentClients.size() + AnonymousClients.size()
			// - 2)) && (temp.load <= min.load)) {
			if (temp.load < min.load) {
				min.id = temp.id;
				min.load = temp.load;
				min.serverload = temp.serverload;
				min.hostname = temp.hostname;
				min.port = temp.port;

			}
		}

		System.out.println(
				"MIn is " + min.id + "  " + min.hostname + "  " + min.load + "  " + min.serverload + "  " + min.port);
		return min;
	}

	private ServerContent checkServerMinload() {
		System.out.println("doing search server with mininum number of load...");

		Iterator iter = AllOtherServers.iterator();

		ServerContent min = new ServerContent(ID, CurrentClients.size() + AnonymousClients.size(),
				CurrentServers.size(), Settings.getLocalHostname(), Settings.getLocalPort());

		while (iter.hasNext()) {
			ServerContent temp = new ServerContent();
			temp = (ServerContent) iter.next();
			log.debug("the current obj is " + temp);
			// if ((temp.load < (CurrentClients.size() + AnonymousClients.size()
			// - 2)) && (temp.load <= min.load)) {
			if (temp.serverload < min.serverload) {
				min.id = temp.id;
				min.load = temp.load;
				min.serverload = temp.serverload;
				min.hostname = temp.hostname;
				min.port = temp.port;

			}
		}

		System.out.println(
				"MIn is " + min.id + "  " + min.hostname + "  " + min.load + "  " + min.serverload + "  " + min.port);
		return min;
	}

	/**
	 * Logout Method (would not have unwantted message, happened by pressing
	 * button)
	 * 
	 * @param con
	 */
	private void Logout(Connection con) {

		if (CurrentClients.contains(con)) {
			Iterator it = CurrentClients.entrySet().iterator();

			while (it.hasNext()) {
				Map.Entry pair = (Map.Entry) it.next();
				if ((Connection) pair.getValue() == con) {
					con.closeCon();
					it.remove();
				}
			}

		}

		System.out.println(CurrentClients.size() + "    SSSSSSSSS");
	}

	/**
	 * the method to send Server Announcement to all other servers
	 */
	public void SendServerAnnounce() {

		int clientload = CurrentClients.size() + AnonymousClients.size();
		int serverload = CurrentServers.size();
		JSONObject obj = new JSONObject();
		obj.put("command", "SERVER_ANNOUNCE");
		obj.put("id", ID);
		obj.put("load", clientload);
		obj.put("serverload", serverload);
		obj.put("hostname", Settings.getLocalHostname());
		obj.put("port", Settings.getLocalPort());

		for (int j = 0; j < CurrentServers.size(); j++) {
			if (isNew.get(CurrentServers.get(j)) == false) {
				CurrentServers.get(j).writeMsg(obj.toJSONString());
			} else {
				CurrentServers.get(j).writeMsg(
						EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(CurrentServers.get(j))).toString());
			}
		}

	}

	/**
	 * the method to deal with received annoucement
	 * 
	 * @param con
	 * @param obj
	 */
	private void ReceiveServerAnnounce(Connection con, JSONObject obj) {
		// check the valid firstly

		System.out.println("Receive Server Announce " + obj.toJSONString());
		String id = (String) obj.get("id");
		ServerContent sc = new ServerContent();
		
//		if (isNew.get(con) == false||obj.size()==5) {
		if(obj.size()==5){
			sc = new ServerContent(id, Integer.parseInt(obj.get("load").toString()),
					1, (String) obj.get("hostname"),
					Integer.parseInt(obj.get("port").toString()));
		} else {
			sc = new ServerContent(id, Integer.parseInt(obj.get("load").toString()), Integer.parseInt(obj.get("serverload").toString()),
					(String) obj.get("hostname"),
					Integer.parseInt(obj.get("port").toString()));
		}
		log.debug("The value of sc is " + sc.hostname + " " + sc.id + " " + sc.load + " " + sc.serverload + " "
				+ sc.port);

		boolean added = false;
		for (ServerContent Newsc : AllOtherServers) {
			if (Newsc.id.equals(sc.id)) {
				Newsc.id = sc.id;
				Newsc.load = sc.load;
				Newsc.serverload = sc.serverload;
				Newsc.hostname = sc.hostname;
				Newsc.port = sc.port;

				added = true;
			}
		}
		if (!added) {

			AllOtherServers.add(sc);
		}

		for (int i = 0; i < CurrentServers.size(); i++) {
			if (CurrentServers.get(i) != con) {
				if (isNew.get(CurrentServers.get(i)) == false) {
					CurrentServers.get(i).writeMsg(obj.toJSONString());
				} else {
					CurrentServers.get(i).writeMsg(
							EncryptionUtil.encyrpt(obj.toJSONString(), KeyList.get(CurrentServers.get(i))).toString());
				}
			}
		}

	}

	/*
	 * if server find it disconnect with its parent,it would send Redirect
	 * message to others,included clients and servers
	 */
	public void ReConnect(Connection con) {

		// check the connection is connected with parent node
		if (con == parentCon) {
			// if so, reconnect to root node
			try {
				System.out.println("New Connection！！！");
				outgoingConnection(new Socket(backuphost, backupport));
			} catch (UnknownHostException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	/*
	 * Called once every few seconds Return true if server should shut down,
	 * false otherwise
	 */
	@Override
	public boolean doActivity() {

		SendServerAnnounce();

		return false;
	}

}
