package org.fogbowcloud.ssh.db;

import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.apache.sshd.SshServer;
import org.fogbowcloud.ssh.TunnelServer;
import org.fogbowcloud.ssh.model.Token;

public class TunnelServerDataStore {

	public static final String TUNNEL_DATASTORE_DRIVER = "org.sqlite.JDBC";
	public static final String TUNNEL_TABLE_NAME = "tb_tunnel_server";
	public static final String SSH_PORT = "ssh_port";
	public static final String TUNNEL_HOST = "tunnel_host";
	public static final String TUNNEL_LOWER_PORT = "lower_port";
	public static final String TUNNEL_HIGHER_PORT = "higher_port";

	private final String CREATE_TABLE_STATEMENT = "CREATE TABLE IF NOT EXISTS " + TUNNEL_TABLE_NAME + " (" 
			+ SSH_PORT + " INTEGER PRIMARY KEY, " 
			+ TUNNEL_HOST + " VARCHAR(50), "
			+ TUNNEL_LOWER_PORT + " INTEGER, " 
			+ TUNNEL_HIGHER_PORT + " INTEGER )";

	private final String INSERT_TUNNEL_SERVER_STATEMENT = "INSERT INTO " + TUNNEL_TABLE_NAME + " VALUES(?, ?, ?, ?)";
	private final String UPDATE_TUNNEL_SERVER_STATEMENT = "UPDATE " + TUNNEL_TABLE_NAME + " SET " + TUNNEL_LOWER_PORT + " = ? , "
			+ TUNNEL_HIGHER_PORT + " = ? WHERE " + SSH_PORT + " = ?";
	private final String SELECT_TUNNEL_SERVER_STATEMENT_ALL = "SELECT * FROM " + TUNNEL_TABLE_NAME;
	private final String DELETE_ALL = "DELETE FROM " + TUNNEL_TABLE_NAME;
	private final String DELETE_TUNNEL_SERVER_STATEMENT_BY_SSHPORT = "DELETE FROM " + TUNNEL_TABLE_NAME + " WHERE " 
			+ SSH_PORT + " = ?";

	private static final Logger LOGGER = Logger.getLogger(TunnelServerDataStore.class);

	private String tunnelDataStoreURL;

	public TunnelServerDataStore(String tunnelDataStoreURL) throws Exception {

		this.tunnelDataStoreURL = tunnelDataStoreURL;

		Statement statement = null;
		Connection connection = null;

		try {

			LOGGER.debug("instanceDataStoreURL: " + this.tunnelDataStoreURL);

			Class.forName(TUNNEL_DATASTORE_DRIVER);

			connection = getConnection();
			statement = connection.createStatement();
			statement.execute(CREATE_TABLE_STATEMENT);
			statement.close();

		} catch (Exception e) {
			LOGGER.error("Error while initializing the DataStore.", e);
			throw e;
		} finally {
			close(statement, connection);
		}
	}

	public void insertTunnelServer(TunnelServer tunnelServer) throws Exception {

		if (tunnelServer == null || tunnelServer.getSshTunnelPort() <= 0 || tunnelServer.getLowerPort() <= 0
				|| tunnelServer.getHigherPort() <= 0) {
			String msg = "Token Id and Token Port must not be null.";
			LOGGER.error(msg);
			throw new Exception(msg);
		}

		LOGGER.debug("Inserting new Tunnel Server [" + tunnelServer.getSshTunnelPort() + "] in host [" + tunnelServer.getSshTunnelHost() + "]");

		PreparedStatement preparedStatement = null;
		Connection connection = null;

		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			preparedStatement = connection.prepareStatement(INSERT_TUNNEL_SERVER_STATEMENT);
			preparedStatement.setInt(1, tunnelServer.getSshTunnelPort());
			preparedStatement.setString(2, tunnelServer.getSshTunnelHost());
			preparedStatement.setInt(3, tunnelServer.getLowerPort());
			preparedStatement.setInt(4, tunnelServer.getHigherPort());
			
			preparedStatement.execute();
			connection.commit();

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + INSERT_TUNNEL_SERVER_STATEMENT, e);
			try {
				if (connection != null) {
					connection.rollback();
				}
			} catch (SQLException e1) {
				LOGGER.error("Couldn't rollback transaction.", e1);
			}
		} finally {
			close(preparedStatement, connection);
		}

	}

	public void updateTokenPort(TunnelServer tunnelServer) throws Exception {

		if (tunnelServer == null || tunnelServer.getSshTunnelPort() == 0 || tunnelServer.getLowerPort() <= 0
				|| tunnelServer.getHigherPort() <= 0) {
			String msg = "Token Id and Token Port must not be null.";
			LOGGER.error(msg);
			throw new Exception(msg);
		}

		LOGGER.debug("Updating Token [" + tunnelServer.getSshTunnelPort() + "] in host [" + tunnelServer.getSshTunnelHost()
				+ "] with ports [" + tunnelServer.getLowerPort() + " to " + tunnelServer.getHigherPort() + "]");

		PreparedStatement preparedStatement = null;
		Connection connection = null;

		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			preparedStatement = connection.prepareStatement(UPDATE_TUNNEL_SERVER_STATEMENT);
			preparedStatement.setInt(1, tunnelServer.getLowerPort());
			preparedStatement.setInt(2, tunnelServer.getHigherPort());
			preparedStatement.setInt(3, tunnelServer.getSshTunnelPort());

			preparedStatement.execute();
			connection.commit();

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + UPDATE_TUNNEL_SERVER_STATEMENT, e);
			try {
				if (connection != null) {
					connection.rollback();
				}
			} catch (SQLException e1) {
				LOGGER.error("Couldn't rollback transaction.", e1);
			}
		} finally {
			close(preparedStatement, connection);
		}

	}

	public List<TunnelServer> getAllTunnelServers() throws Exception {

		LOGGER.debug("Select all Tunnels ports.");

		return executeQueryStatement(SELECT_TUNNEL_SERVER_STATEMENT_ALL, new String[0]);

	}

	public TunnelServer getTunnelServerByPort(Integer port) throws SQLException {

		LOGGER.debug("Getting Tunnel port by Port [" + port + "]");

		StringBuilder queryStatement = new StringBuilder(SELECT_TUNNEL_SERVER_STATEMENT_ALL);
		queryStatement.append(" WHERE ");
		queryStatement.append(SSH_PORT);
		queryStatement.append(" = ?");

		List<TunnelServer> tunnelServers = executeQueryStatement(queryStatement.toString(), String.valueOf(port));

		if (tunnelServers != null && !tunnelServers.isEmpty()) {
			return tunnelServers.get(0);
		}
		return null;
	}
	
	public boolean deleteAll() throws Exception {

		LOGGER.debug("Deleting all Tokens");

		PreparedStatement preparedStatement = null;
		Connection connection = null;
		
		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			preparedStatement = connection.prepareStatement(DELETE_ALL);
			
			preparedStatement.execute();
			connection.commit();
			
			return true;

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + DELETE_ALL, e);
			try {
				if (connection != null) {
					connection.rollback();
				}
			} catch (SQLException e1) {
				LOGGER.error("Couldn't rollback transaction.", e1);
			}
		} finally {
			close(preparedStatement, connection);
		}
		return false;

	}
	
	public boolean deleteTunnelServer(TunnelServer tunnelServer) throws Exception {

		if (tunnelServer == null || tunnelServer.getSshTunnelPort() <= 0) {
			String msg = "Tunnel can not be null.";
			LOGGER.error(msg);
			throw new Exception(msg);
		}

		LOGGER.debug("Deleting Token [" + tunnelServer.getSshTunnelPort() + "] in host [" + tunnelServer.getSshTunnelHost()
		+ "] with ports [" + tunnelServer.getLowerPort() + " to " + tunnelServer.getHigherPort() + "]");

		PreparedStatement preparedStatement = null;
		Connection connection = null;
		
		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			preparedStatement = connection.prepareStatement(DELETE_TUNNEL_SERVER_STATEMENT_BY_SSHPORT);
			preparedStatement.setInt(1, tunnelServer.getSshTunnelPort());
			
			preparedStatement.execute();
			connection.commit();
			
			return true;

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + DELETE_TUNNEL_SERVER_STATEMENT_BY_SSHPORT, e);
			try {
				if (connection != null) {
					connection.rollback();
				}
			} catch (SQLException e1) {
				LOGGER.error("Couldn't rollback transaction.", e1);
			}
		} finally {
			close(preparedStatement, connection);
		}
		return false;

	}
	
	public int deleteListOfTunnels(List<TunnelServer> tunnelServers) throws Exception {

		if (tunnelServers == null || tunnelServers.isEmpty()) {
			LOGGER.error("There are no tokens to delete.");
			return 0;
		}

		PreparedStatement preparedStatement = null;
		Connection connection = null;
		
		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			for(TunnelServer tunnelServer : tunnelServers){
				preparedStatement = connection.prepareStatement(DELETE_TUNNEL_SERVER_STATEMENT_BY_SSHPORT);
				preparedStatement.setInt(1, tunnelServer.getSshTunnelPort());
				preparedStatement.addBatch();
			}
			int bachExecution[] = preparedStatement.executeBatch();
			if(hasBatchExecutionError(bachExecution)){
				connection.rollback();
				return 0;
			}
			connection.commit();
			
			return bachExecution.length;

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + DELETE_TUNNEL_SERVER_STATEMENT_BY_SSHPORT, e);
			try {
				if (connection != null) {
					connection.rollback();
				}
			} catch (SQLException e1) {
				LOGGER.error("Couldn't rollback transaction.", e1);
			}
		} finally {
			close(preparedStatement, connection);
		}
		return 0;

	}
	
	private List<TunnelServer> executeQueryStatement(String queryStatement, String... params) throws SQLException {

		PreparedStatement preparedStatement = null;
		Connection conn = null;
		List<TunnelServer> tokensPorts = new ArrayList<TunnelServer>();

		try {

			conn = getConnection();
			preparedStatement = conn.prepareStatement(queryStatement);

			if (params != null && params.length > 0) {
				for (int index = 0; index < params.length; index++) {
					preparedStatement.setString(index + 1, params[index]);
				}
			}

			ResultSet rs = preparedStatement.executeQuery();

			if (rs != null) {
				try {
					tokensPorts = this.mountTunnelServer(rs);
				} catch (Exception e) {
					LOGGER.error("Error while mounting instande from DB.", e);
				}
			}

		} catch (SQLException e) {
			LOGGER.error("Couldn't get Tokens ports.", e);
			throw e;
		} finally {
			close(preparedStatement, conn);
		}
		return tokensPorts;
	}

	private List<TunnelServer> mountTunnelServer(ResultSet rs) {

		List<TunnelServer> tokensPorts = new ArrayList<TunnelServer>();
		
		if (rs != null) {
			try {
				while (rs.next()) {

					TunnelServer tunnelServer = new TunnelServer(rs.getString(TUNNEL_HOST), rs.getInt(SSH_PORT), 
							rs.getInt(TUNNEL_LOWER_PORT), rs.getInt(TUNNEL_HIGHER_PORT), null, null, new ArrayList<Token>());
					tokensPorts.add(tunnelServer);
				}
			} catch (Exception e) {
				LOGGER.error("Error while mounting instande from DB.", e);
			}
		}
		
		return tokensPorts;
	}
	
	private boolean hasBatchExecutionError(int[] executeBatch) {
		for (int i : executeBatch) {
			if (i == PreparedStatement.EXECUTE_FAILED) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return the connection
	 * @throws SQLException
	 */
	public Connection getConnection() throws SQLException {
		try {
			return DriverManager.getConnection(tunnelDataStoreURL);
		} catch (SQLException e) {
			LOGGER.error("Error while getting a new connection from the connection pool.", e);
			throw e;
		}
	}

	private void close(Statement statement, Connection conn) {
		if (statement != null) {
			try {
				if (!statement.isClosed()) {
					statement.close();
				}
			} catch (SQLException e) {
				LOGGER.error("Couldn't close statement");
			}
		}

		if (conn != null) {
			try {
				if (!conn.isClosed()) {
					conn.close();
				}
			} catch (SQLException e) {
				LOGGER.error("Couldn't close connection");
			}
		}
	}
}
