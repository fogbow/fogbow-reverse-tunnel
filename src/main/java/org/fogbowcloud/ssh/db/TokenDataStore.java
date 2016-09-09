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
import org.fogbowcloud.ssh.model.Token;

public class TokenDataStore {

	public static final String TOKEN_DATASTORE_DRIVER = "org.sqlite.JDBC";
	public static final String TOKEN_TABLE_NAME = "tb_token_port";
	public static final String TOKEN_ID = "token_id";
	public static final String PORT = "port";
	public static final String SSH_SERVER_PORT = "ssh_server_port";
	public static final String LAST_ACTIVE_SESSION = "last_active_session";

	private final String CREATE_TABLE_STATEMENT = "CREATE TABLE IF NOT EXISTS " + TOKEN_TABLE_NAME + " (" + TOKEN_ID
			+ " VARCHAR(255) PRIMARY KEY, " + PORT + " INTEGER, " + SSH_SERVER_PORT + " INTEGER, " + LAST_ACTIVE_SESSION
			+ " INTEGER)";

	private final String INSERT_TOKEN_PORT_STATEMENT = "INSERT INTO " + TOKEN_TABLE_NAME + " VALUES(?, ?, ?, ?)";
	private final String UPDATE_TOKEN_PORT_STATEMENT = "UPDATE " + TOKEN_TABLE_NAME + " SET " + PORT + " = ? , "
			+ SSH_SERVER_PORT + " = ? , " + LAST_ACTIVE_SESSION + " = ? WHERE " + TOKEN_ID + " = ?";
	private final String SELECT_TOKEN_PORT_STATEMENT_ALL = "SELECT * FROM " + TOKEN_TABLE_NAME;
	private final String DELETE_ALL = "DELETE FROM " + TOKEN_TABLE_NAME;
	private final String DELETE_TOKEN_PORT_STATEMENT_BY_TOKEN = "DELETE FROM " + TOKEN_TABLE_NAME + " WHERE " + TOKEN_ID
			+ " = ?";

	private static final Logger LOGGER = Logger.getLogger(TokenDataStore.class);

	private String tokenDataStoreURL;

	public TokenDataStore(String tokenDataStoreURL) throws Exception {

		this.tokenDataStoreURL = tokenDataStoreURL;

		Statement statement = null;
		Connection connection = null;

		try {

			LOGGER.debug("instanceDataStoreURL: " + this.tokenDataStoreURL);

			Class.forName(TOKEN_DATASTORE_DRIVER);

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

	public void insertTokenPort(Token token) throws Exception {

		if (token == null || token.getTokenId() == null || token.getPort() == null) {
			String msg = "Token Id and Token Port must not be null.";
			LOGGER.error(msg);
			throw new Exception(msg);
		}

		LOGGER.debug("Inserting new Token [" + token.getTokenId() + "] with port [" + token.getPort() + "]");

		PreparedStatement preparedStatement = null;
		Connection connection = null;

		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			preparedStatement = connection.prepareStatement(INSERT_TOKEN_PORT_STATEMENT);
			preparedStatement.setString(1, token.getTokenId());
			preparedStatement.setInt(2, token.getPort());
			preparedStatement.setInt(3, token.getSshServerPort());
			preparedStatement.setLong(4, token.getLastIdleCheck());

			preparedStatement.execute();
			connection.commit();

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + INSERT_TOKEN_PORT_STATEMENT, e);
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

	public void updateTokenPort(Token token) throws Exception {

		if (token == null || token.getTokenId() == null || token.getPort() == null) {
			String msg = "Token Id and Token Port must not be null.";
			LOGGER.error(msg);
			throw new Exception(msg);
		}

		LOGGER.debug("Updating Token [" + token.getTokenId() + "] with port [" + token.getPort()
				+ "] and Last Active Session [" + token.getLastIdleCheck() + "]");

		PreparedStatement preparedStatement = null;
		Connection connection = null;

		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			preparedStatement = connection.prepareStatement(UPDATE_TOKEN_PORT_STATEMENT);
			preparedStatement.setInt(1, token.getPort());
			preparedStatement.setInt(2, token.getSshServerPort());
			preparedStatement.setLong(3, token.getLastIdleCheck());
			preparedStatement.setString(4, token.getTokenId());

			preparedStatement.execute();
			connection.commit();

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + UPDATE_TOKEN_PORT_STATEMENT, e);
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

	public List<Token> getAllTokenPorts() throws Exception {

		LOGGER.debug("Select all Tokens ports.");

		return executeQueryStatement(SELECT_TOKEN_PORT_STATEMENT_ALL+" order by "+SSH_SERVER_PORT, new String[0]);

	}
	
	public List<Token> getAllTokenPortsBySshServerPort(Integer sshServerPort) throws Exception {

		LOGGER.debug("Select all Tokens ports from ssh server port[" + sshServerPort + "].");

		StringBuilder queryStatement = new StringBuilder(SELECT_TOKEN_PORT_STATEMENT_ALL);
		queryStatement.append(" WHERE ");
		queryStatement.append(SSH_SERVER_PORT);
		queryStatement.append(" = ?");
		queryStatement.append(" order by "+SSH_SERVER_PORT);
		
		return executeQueryStatement(queryStatement.toString(), String.valueOf(sshServerPort));

	}

	public Token getTokenPortByTokenId(String tokenId) throws SQLException {

		LOGGER.debug("Getting token port by Token ID [" + tokenId + "]");

		StringBuilder queryStatement = new StringBuilder(SELECT_TOKEN_PORT_STATEMENT_ALL);
		queryStatement.append(" WHERE ");
		queryStatement.append(TOKEN_ID);
		queryStatement.append(" = ?");
		queryStatement.append(" order by "+SSH_SERVER_PORT);

		List<Token> tokensPorts = executeQueryStatement(queryStatement.toString(), tokenId);

		if (tokensPorts != null && !tokensPorts.isEmpty()) {
			return tokensPorts.get(0);
		}
		return null;
	}

	public Token getTokenPortByPort(Integer port) throws SQLException {

		LOGGER.debug("Getting token port by Token Port [" + port + "]");

		StringBuilder queryStatement = new StringBuilder(SELECT_TOKEN_PORT_STATEMENT_ALL);
		queryStatement.append(" WHERE ");
		queryStatement.append(PORT);
		queryStatement.append(" = ?");
		queryStatement.append(" order by "+SSH_SERVER_PORT);

		List<Token> tokensPorts = executeQueryStatement(queryStatement.toString(), port);

		if (tokensPorts != null && !tokensPorts.isEmpty()) {
			return tokensPorts.get(0);
		}
		return null;
	}
	
	public boolean deleteAll() throws Exception {


		LOGGER.debug("Deleting all tokens");

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

	public boolean deleteTokenPort(Token token) throws Exception {

		if (token == null || token.getTokenId() == null) {
			String msg = "Token Id and Token Port must not be null.";
			LOGGER.error(msg);
			throw new Exception(msg);
		}

		LOGGER.debug("Deleting Token [" + token.getTokenId() + "] with port [" + token.getPort()
				+ "] and Last Active Session [" + token.getLastIdleCheck() + "]");

		PreparedStatement preparedStatement = null;
		Connection connection = null;

		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			preparedStatement = connection.prepareStatement(DELETE_TOKEN_PORT_STATEMENT_BY_TOKEN);
			preparedStatement.setString(1, token.getTokenId());

			preparedStatement.execute();
			connection.commit();

			return true;

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + DELETE_TOKEN_PORT_STATEMENT_BY_TOKEN, e);
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

	public int deleteListOfTokenPort(List<Token> tokens) throws Exception {

		if (tokens == null || tokens.isEmpty()) {
			LOGGER.error("There are no tokens to delete.");
			return 0;
		}

		PreparedStatement preparedStatement = null;
		Connection connection = null;

		try {

			connection = getConnection();
			connection.setAutoCommit(false);
			for (Token token : tokens) {
				preparedStatement = connection.prepareStatement(DELETE_TOKEN_PORT_STATEMENT_BY_TOKEN);
				preparedStatement.setString(1, token.getTokenId());
				preparedStatement.addBatch();
			}
			int bachExecution[] = preparedStatement.executeBatch();
			if (hasBatchExecutionError(bachExecution)) {
				connection.rollback();
				return 0;
			}
			connection.commit();

			return bachExecution.length;

		} catch (SQLException e) {
			LOGGER.error("Couldn't execute statement : " + DELETE_TOKEN_PORT_STATEMENT_BY_TOKEN, e);
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

	private List<Token> executeQueryStatement(String queryStatement, Object... params) throws SQLException {

		PreparedStatement preparedStatement = null;
		Connection conn = null;
		List<Token> tokensPorts = new ArrayList<Token>();

		try {

			conn = getConnection();
			preparedStatement = conn.prepareStatement(queryStatement);

			if (params != null && params.length > 0) {
				for (int index = 0; index < params.length; index++) {
					Object param = params[index];
					if(param instanceof String){
						preparedStatement.setString(index+1, (String) params[index]);
					}
					if(param instanceof Integer){
						preparedStatement.setInt(index+1, (Integer) params[index]);
					}
					if(param instanceof Long){
						preparedStatement.setLong(index+1, (Long) params[index]);
					}
					if(param instanceof java.sql.Date){
						preparedStatement.setDate(index+1, (java.sql.Date) params[index]);
					}
					
				}
			}

			ResultSet rs = preparedStatement.executeQuery();

			if (rs != null) {
				try {
					tokensPorts = mountTokenPorts(rs);
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

	private List<Token> mountTokenPorts(ResultSet rs) {

		List<Token> tokensPorts = new ArrayList<Token>();
		
		if (rs != null) {
			try {
				while (rs.next()) {

					Token token = new Token(rs.getString(TOKEN_ID), rs.getInt(PORT), rs.getInt(SSH_SERVER_PORT));
					token.setLastIdleCheck(rs.getLong(LAST_ACTIVE_SESSION));
					
					tokensPorts.add(token);
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
			return DriverManager.getConnection(tokenDataStoreURL);
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
