package activitystreamer.server;

import java.io.IOException;
import java.net.Socket;
import java.time.chrono.MinguoChronology;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class ControlSolution extends Control {

	public class ServerContent {

		String id;
		int load;
		String hostname;
		int port;

		public ServerContent() {
		}

		public ServerContent(String id, int load, String hostname, int port) {
			this.id = id;
			this.load = load;
			this.hostname = hostname;
			this.port = port;
		}

	}

	//////

	private static final Logger log = LogManager.getLogger();

	private static Hashtable<String, String> AllUserList;
	private static ArrayList<Connection> AnonymousClients;;
	private static Hashtable<String, Connection> CurrentClients;

	private static ArrayList<Connection> CurrentServers;
	private static ArrayList<ServerContent> AllOtherServers;

	private JSONParser parser = new JSONParser();
	// the secret for all server network
	private String SSecret;
	private String ID;

	private String[] waitingClient = waitingClient = new String[2];
	private int counter, counter1;
	private boolean lockis = true;

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
		initiateConnection();
		// start the server's activity loop
		// it will call doActivity every few seconds
		start();
	}

	/*
	 * a new incoming connection
	 */
	@Override
	public Connection incomingConnection(Socket s) throws IOException {
		Connection con = super.incomingConnection(s);

		System.out.println("I receive a incomming connection");

		return con;
	}

	/*
	 * a new outgoing connection
	 */
	@Override
	public Connection outgoingConnection(Socket s) throws IOException {
		Connection con = super.outgoingConnection(s);

		sendAuthenticateMsg(con, Settings.getSecret());

		CurrentServers.add(con);

		return con;
	}

	private void sendAuthenticateMsg(Connection con, String secret) {
		// TODO Auto-generated method stub
		JSONObject obj = new JSONObject();
		obj.put("command", "AUTHENTICATE");
		obj.put("secret", secret);

		con.writeMsg(obj.toJSONString());
	}

	/*
	 * the connection has been closed
	 */
	@Override
	public void connectionClosed(Connection con) {
		super.connectionClosed(con);

		if (CurrentClients.contains(con)) {
			CurrentClients.remove(con);
		}
	}

	/*
	 * process incoming msg, from connection con return true if the connection
	 * should be closed, false otherwise
	 */
	@Override
	public synchronized boolean process(Connection con, String msg) {

		/*
		 * cut the String into command + username +content
		 */
		JSONObject obj;

		try {
			obj = (JSONObject) parser.parse(msg);
			if (!obj.containsKey("command")) {
				sendMessage(con, "INVALID_MESSAGE", "the received message did not contain a command");
			} else {
				String coms = (String) obj.get("command");

				switch (coms) {
				case "AUTHENTICATE":

					ReceiveAuthenticate(con, obj);
					break;

				case "LOGIN":

					Login(con, obj);
					break;

				case "LOGOUT":

					Logout(con, obj);
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
					// sendMessage(con, "INVALID_MESSAGE", "You send a invalid
					// message");
					// connectionClosed(con);
					break;
				}
			}

		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			sendMessage(con, "INVALID_MESSAGE", "JSON parse error while parsing message");
			connectionClosed(con);
		}

		return false;
	}

	private void ReceiveLockDenied(JSONObject obj) {

		if (obj.get("username") != null && obj.get("secret") != null) {
			System.out.println("Receive Lock Denide for " + obj.get("username") + " :" + obj.get("secret"));
			// receive the message is from my request
			if (waitingClient[0].equals(obj.get("username"))) {
				counter++;
				lockis = false;
				AllUserList.remove(waitingClient[0], waitingClient[1]);
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
			if (waitingClient[0].equals(obj.get("username"))) {
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
		boolean islocked = false;
		// using array to store waiting client ' username and secret

		if (waitingClient[0] != null && waitingClient[1] != null) {
			System.out.println("Receive Lock Request for " + obj.get("username") + " :" + obj.get("secret"));
			if (AllUserList.get("username").equals(waitingClient[0])) {
				islocked = true;
			}
		} else {
			log.info("no username or secret");
			AllUserList.put((String) obj.get("username"), (String) obj.get("secret"));
		}
		if (islocked == true)
			sendLockDenied(waitingClient[0], waitingClient[1]);
		else
			sendLockAllowed(waitingClient[0], waitingClient[1]);

	}

	public void SendLockRequest(String username, String secret) {
		// TODO Auto-generated method stub
		System.out.println("now begin to send lock request");
		waitingClient[0] = username;
		waitingClient[1] = secret;
		// chech self
		// check other servers
		if (CurrentServers.size() != 0) {
			JSONObject obj = new JSONObject();
			obj.put("command", "LOCK_REQUEST");
			obj.put("username", username);
			obj.put("secret", secret);

			for (int i = 0; i < CurrentServers.size(); i++) {
				CurrentServers.get(i).writeMsg(obj.toJSONString());
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
			CurrentServers.get(i).writeMsg(obj.toJSONString());
		}
	}

	private void sendLockDenied(String currentUser, String currentSec) {
		JSONObject obj = new JSONObject();
		obj.put("command", "LOCK_DENIED");
		obj.put("username", currentUser);
		obj.put("secret", currentSec);
		obj.put("server", ID);

		for (int i = 0; i < CurrentServers.size(); i++) {
			CurrentServers.get(i).writeMsg(obj.toJSONString());
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
			CurrentServers.get(j).writeMsg(js.toJSONString());

		}

		for (int j = 0; j < AnonymousClients.size(); j++) {
			AnonymousClients.get(j).writeMsg(js.toJSONString());

		}

		Iterator iter = CurrentClients.keySet().iterator();
		while (iter.hasNext()) {

			Connection con = (Connection) iter.next();
			con.writeMsg(js.toJSONString());
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
				CurrentServers.get(j).writeMsg(js.toJSONString());
			}

		}
		for (int j = 0; j < AnonymousClients.size(); j++) {
			AnonymousClients.get(j).writeMsg(js.toJSONString());

		}

		Iterator iter = CurrentClients.keySet().iterator();
		while (iter.hasNext()) {

			Connection con = (Connection) iter.next();
			con.writeMsg(js.toJSONString());
		}
	}

	/**
	 * the method to deal with the received activity broadcast
	 * 
	 * @param con
	 * @param obj
	 */
	private void ReceiveActivityBroadCast(Connection con, JSONObject obj) {
		if (AllOtherServers.contains(con)) {
			System.out.println("Received Activity Object is: " + obj.get("activity"));
			sendActivityBroadcast(con, obj);

		} else {
			sendMessage(con, "INVALID_MESSAGE", "The server is not authenticated");
			connectionClosed(con);
		}
	}

	/**
	 * The method to handle received authenticate message
	 * 
	 * @param con
	 * @param obj
	 */
	private void ReceiveAuthenticate(Connection con, JSONObject obj) {

		// this server is root server
		if (obj.get("secret").equals(SSecret)) {

			CurrentServers.add(con);
		} else if (obj.get("secret").equals(Settings.getSecret())) {
			SSecret = Settings.getSecret();
			CurrentServers.add(con);
		} else {

			sendMessage(con, "AUTHENTICATION_FAIL", "the supplied secret is incorrect:" + obj.get("secret"));
			con.closeCon();// should we consider close this thread?
		}

	}

	private void sendMessage(Connection con, String command, String info) {

		JSONObject obj = new JSONObject();
		obj.put("command", command);
		obj.put("info", info);

		System.out.println("object is " + obj.toJSONString());
		con.writeMsg(obj.toJSONString());
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
			if (!(AllUserList.containsKey(username) && waitingClient[0].equals(username))) {
				AllUserList.put(username, secret);
				SendLockRequest(username, secret);

				// waiting for response
				try {
					this.wait(5000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				// chech the lock success or be denied
				if ((counter + counter1) == AllOtherServers.size()) {
					if (lockis == true) {
						// log.info("Register 1 user:" + username);
						sendMessage(con, "REGISTER_SUCCESS", "register success for " + username);

					} else {
						AllUserList.remove(username, secret);
						sendMessage(con, "REGISTER_FAILED", "The username or secret you input has already exsited");
					}
				} else {
					log.info("Not all server response in time");

					sendMessage(con, "REGISTER_SUCCESS", "register success for " + username);
				}
			} else
				sendMessage(con, "REGISTER_FAILED", "The username or secret you input has already exsited");

		} else
			sendMessage(con, "REGISTER_FAILED", "The username or secret you input is invalid");

	}

	/**
	 * Login method
	 */
	// public void Login(Connection con, JSONObject obj) {
	// // check the user need to be added
	// boolean isAnon = false;
	// String usern = (String) obj.get("username");
	// String sec = (String) obj.get("secret");
	//
	// if ((usern.equals("anonymous") || usern.equals("Anonymous")) && sec ==
	// null) {
	// isAnon = true;
	// } else {
	// // check the message is valid or not
	// if (usern != null && sec != null) {
	// // check the user has already login or not
	// if (AllUserList.containsKey(usern) && AllUserList.get(usern).equals(sec))
	// {
	//
	// }
	//
	// } else {
	// sendMessage(con, "INVALID_MESSAGE", "The username or secret you input is
	// invalid");
	// }
	// }
	//
	// // check current server' load and
	// if (CurrentClients.size() <= 2 || (CurrentClients.size() > 2 &&
	// checkMinload().id == ID)) {
	// // not do redirection
	// if (isAnon == false) {
	// CurrentClients.put(usern, con);
	// sendMessage(con, "LOGIN_SUCCESS", "logged in as user " + usern);
	//
	// } else {
	// AnonymousClients.add(con);
	// sendMessage(con, "LOGIN_SUCCESS", "logged in as anonymous ");
	// }
	// } else {
	// // do redirection
	// ServerContent sc = checkMinload();
	// JSONObject o = new JSONObject();
	// o.put("command", "REDIRECT");
	// o.put("hostname", sc.hostname);
	// o.put("port", sc.port);
	// con.writeMsg(o.toJSONString());
	// System.out.println("now to redirect!!!");
	//
	// }
	// }
	//

	public void Login(Connection con, JSONObject obj) {
		int load = CurrentClients.size() + AnonymousClients.size();

		// check the anonymous user
		if ((obj.get("username").equals("anonymous") || obj.get("username").equals("Anonymous"))
				&& obj.get("secret") == null) {

			if (load <= 2 || (load > 2 && checkMinload().id == ID)) {
				AnonymousClients.add(con);
				sendMessage(con, "LOGIN_SUCCESS", "logged in as anonymous");
			} else {
				// do redirect
				ServerContent sc = checkMinload();
				JSONObject o = new JSONObject();
				o.put("command", "REDIRECT");
				o.put("hostname", sc.hostname);
				o.put("port", sc.port);
				con.writeMsg(o.toJSONString());
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
						if (load <= 2 || (load > 2 && checkMinload().id == ID)) {
							CurrentClients.put(usern, con);
							sendMessage(con, "LOGIN_SUCCESS", "logged in as anonymous");
						} else {
							// do redirect
							ServerContent sc = checkMinload();
							JSONObject o = new JSONObject();
							o.put("command", "REDIRECT");
							o.put("hostname", sc.hostname);
							o.put("port", sc.port);
							con.writeMsg(o.toJSONString());
							System.out.println("now to redirect!!!");
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
	private ServerContent checkMinload() {
		System.out.println("doing search server with mininum number of load...");

		Iterator iter = AllOtherServers.iterator();

		ServerContent min = new ServerContent("", Integer.MAX_VALUE, "", 0);

		int newLoad = Integer.MAX_VALUE;

		while (iter.hasNext()) {

			ServerContent temp = new ServerContent();
			temp = (ServerContent) iter.next();
			log.debug("the current obj is " + temp);
			if ((temp.load <= (CurrentClients.size() - 2)) && (temp.load <= newLoad)) {
				newLoad = temp.load;
				min.id = temp.id;
				min.load = temp.load;
				min.hostname = temp.hostname;
				min.port = temp.port;

			}
		}

		System.out.println("MIn is " + min.id + "  " + min.hostname + "  " + min.load + "  " + min.port);
		return min;
	}

	/**
	 * Logout Method (would not have unwantted message, happened by pressing
	 * button)
	 * 
	 * @param con
	 */
	private void Logout(Connection con, JSONObject obj) {
		if (CurrentClients.containsKey(obj.get("username"))) {
			CurrentClients.remove(obj.get("username"));
			connectionClosed(con);
		}

	}

	/**
	 * the method to send Server Announcement to all other servers
	 */
	public void SendServerAnnounce() {

		JSONObject obj = new JSONObject();
		obj.put("command", "SERVER_ANNOUNCE");
		obj.put("id", ID);
		obj.put("load", CurrentClients.size());
		obj.put("hostname", Settings.getLocalHostname());
		obj.put("port", Settings.getLocalPort());

		for (int j = 0; j < CurrentServers.size(); j++) {
			CurrentServers.get(j).writeMsg(obj.toJSONString());
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

		ServerContent sc = new ServerContent(id, Integer.parseInt(obj.get("load").toString()),
				(String) obj.get("hostname"), Integer.parseInt(obj.get("port").toString()));
		log.debug("The value of sc is " + sc.hostname + " " + sc.id + " " + sc.load + " " + sc.port);

		boolean added = false;
		for (ServerContent Newsc : AllOtherServers) {
			if (Newsc.id.equals(sc.id)) {
				Newsc.id = sc.id;
				Newsc.load = sc.load;
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
				CurrentServers.get(i).writeMsg(obj.toJSONString());
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
