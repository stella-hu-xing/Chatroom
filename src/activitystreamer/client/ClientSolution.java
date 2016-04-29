package activitystreamer.client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.server.Control;
import activitystreamer.util.Settings;

public class ClientSolution extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSolution clientSolution;
	private TextFrame textFrame;

	private Socket clientSocket;

	public String Username;
	public String Secret;

	private DataInputStream in;
	private DataOutputStream out;
	private BufferedReader inreader;
	private PrintWriter outwriter;

	private JSONParser parser = new JSONParser();

	// this is a singleton object
	public static ClientSolution getInstance() throws UnknownHostException, IOException {
		if (clientSolution == null) {
			clientSolution = new ClientSolution();

		}
		return clientSolution;
	}

	public ClientSolution() throws UnknownHostException, IOException {

		textFrame = new TextFrame();

		clientSocket = new Socket(Settings.getRemoteHostname(), Settings.getRemotePort());

		Username = Settings.getUsername();
		Secret = Settings.getSecret();

		in = new DataInputStream(clientSocket.getInputStream());
		out = new DataOutputStream(clientSocket.getOutputStream());
		inreader = new BufferedReader(new InputStreamReader(in));
		outwriter = new PrintWriter(out, true);
		if (Secret == null && !(Username.equals("Anonymous") || Username.equals("anonymous"))) {
			sendRegisterRequest();
		} else
			sendLoginRequest();
		// start the client's thread
		start();
	}

	// reaction of receiving messages form server
	/*
	 * process incoming msg, from connection con return true if the connection
	 * should be closed, false otherwise
	 */
	public void process(String data) {

		JSONObject obj;
		JSONParser parser = new JSONParser();
		try {
			obj = (JSONObject) parser.parse(data);

			String coms = (String) obj.get("command");
			if (coms != null) {
				switch (coms) {

				case "INVALID_MESSAGE":
					// disconnect();
					break;

				case "REGISTER_FAILED":
					textFrame.setOutputText(obj);
					failed(obj);
					break;

				case "LOGIN_FAILED":
					textFrame.setOutputText(obj);
					failed(obj);
					break;

				case "REGISTER_SUCCESS":
					textFrame.setOutputText(obj);

					try {
						sendLoginRequest();
					} catch (UnknownHostException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

					break;

				case "LOGIN_SUCCESS":

					textFrame.setOutputText(obj);
					break;

				case "REDIRECT":
					textFrame.setOutputText(obj);
					try {
						DoRedirect(obj);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					break;

				case "ACTIVITY_BROADCAST":
					textFrame.setOutputText(obj);
					break;
				}

			} else {
				// log.info("receive invalid message" + obj.toJSONString());
			}
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private void failed(JSONObject obj) {

		try {
			disconnect();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * deal with redirect
	 * 
	 * @param obj
	 * @throws IOException
	 */
	private void DoRedirect(JSONObject obj) throws IOException {

		String hn = (String) obj.get("hostname");
		int port = (int) (long) obj.get("port");
		// clientSocket.close();
		clientSocket = new Socket(hn, port);
		in = new DataInputStream(clientSocket.getInputStream());
		out = new DataOutputStream(clientSocket.getOutputStream());
		inreader = new BufferedReader(new InputStreamReader(in));
		outwriter = new PrintWriter(out, true);
		sendLoginRequest();

	}

	// called by the gui when the user clicks disconnect
	public void disconnect() throws IOException {

		textFrame.setVisible(false);
		JSONObject object = new JSONObject();
		object.put("command", "LOGOUT");
		outwriter.println(object.toJSONString());
		outwriter.flush();
		clientSocket.close();

	}

	// sendRegisterRequest
	public void sendRegisterRequest() throws UnknownHostException, IOException {
		// check anonymous
		if (Username.equals("anonymous") || Username.equals("Anonymous")) {

			log.info("Client cannot register as 'anonymous'");
		} else {
			JSONObject obj = new JSONObject();
			obj.put("command", "REGISTER");
			obj.put("username", Username);
			Secret = Settings.nextSecret();
			log.info("Secret for " + Username + " is " + Secret);
			obj.put("secret", Secret);

			outwriter.println(obj.toJSONString());
			outwriter.flush();

		}
	}

	// send log in request
	public void sendLoginRequest() throws UnknownHostException, IOException {
		JSONObject obj = new JSONObject();
		obj.put("command", "LOGIN");
		if (Username.equals("anonymous") || Username.equals("Anonymous")) {
			obj.put("username", Username);

		} else {
			obj.put("username", Username);
			obj.put("secret", Secret);

		}
		System.out.println(clientSocket.getPort());
		outwriter.println(obj.toJSONString());
		outwriter.flush();
	}

	// called by the gui when the user clicks "send"
	public void sendActivityObject(JSONObject activityObj) throws IOException, Exception {

		JSONObject obj = new JSONObject();
		obj.put("command", "ACTIVITY_MESSAGE");
		obj.put("username", Username);
		obj.put("secret", Secret);
		obj.put("activity", activityObj);

		outwriter.println(obj.toJSONString());
		outwriter.flush();
	}

	// the client's run method, to receive messages
	@Override
	public void run() {
		String data;

		try {
			while ((data = inreader.readLine()) != null) {
				System.out.println("received:" + data);
				process(data);
				try {
					JSONObject obj = (JSONObject) parser.parse(data);

				} catch (ParseException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
