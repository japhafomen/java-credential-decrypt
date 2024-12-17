package montest;

public class DecryptedData {
private String hostname;
private String username;
private String password;
public DecryptedData(String hostname, String username, String password) {
	super();
	this.hostname = hostname;
	this.username = username;
	this.password = password;
}
public String getHostname() {
	return hostname;
}
public String getUsername() {
	return username;
}
public String getPassword() {
	return password;
}

	
}
