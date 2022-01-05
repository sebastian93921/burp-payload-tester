package payloadtester;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.List;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import burp.*;
import com.google.gson.*;

import static burp.IParameter.PARAM_URL;
import static burp.IRequestInfo.CONTENT_TYPE_NONE;
import static burp.IRequestInfo.CONTENT_TYPE_URL_ENCODED;
import static javax.swing.JTable.AUTO_RESIZE_NEXT_COLUMN;
import static javax.swing.JTable.AUTO_RESIZE_OFF;


public class PayloadTester extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController, IContextMenuFactory{
    public static final int textHeight = new JTextField().getPreferredSize().height;
    private static final String WORDLIST_SETTING = "burp-payload-tester-wordlist";

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private Table logTable;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

    // UI Related
    private JTabbedPane tabbedPane;
    private JTextArea payloadArea;
    private JTextField msBetweenEachRequest;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.helpers = callbacks.getHelpers();
        this.stdout.println("Sebastian - PayloadTester?");
        this.stdout.println("Please place proper payload into test strings");
        callbacks.setExtensionName("PayloadTester");
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);

        SwingUtilities.invokeLater(new Runnable(){
            @Override
            public void run() {
                tabbedPane = new JTabbedPane();

                // Main panel
                JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                logTable = new Table(PayloadTester.this);
                {
                    logTable.setAutoResizeMode(AUTO_RESIZE_OFF);
                    logTable.getColumnModel().getColumn(0).setPreferredWidth(80);
                    logTable.getColumnModel().getColumn(1).setPreferredWidth(400);
                    logTable.getColumnModel().getColumn(2).setPreferredWidth(400);
                    logTable.getColumnModel().getColumn(3).setPreferredWidth(90);
                    logTable.getColumnModel().getColumn(4).setPreferredWidth(100);
                    logTable.getColumnModel().getColumn(5).setPreferredWidth(150);
                }
                // Popup menu
                final JPopupMenu popupMenu = new JPopupMenu();
                JMenuItem clearHistory = new JMenuItem("Clear history");
                clearHistory.addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        stdout.println("Clear all table records.");
                        log.clear();
                        fireTableDataChanged();
                    }
                });
                popupMenu.add(clearHistory);
                logTable.setComponentPopupMenu(popupMenu);

                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                JTabbedPane tabs = new JTabbedPane();
                requestViewer = PayloadTester.this.callbacks.createMessageEditor(PayloadTester.this, false);
                responseViewer = PayloadTester.this.callbacks.createMessageEditor(PayloadTester.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);


                // Option panel
                JPanel optionPanel = new JPanel();
                optionPanel.setLayout(new BoxLayout(optionPanel, BoxLayout.Y_AXIS));

                JPanel payloadTitlePanel = new JPanel();
                JLabel payloadTitle = new JLabel("Payload list (Please place in line by line)");
                payloadTitlePanel.add(payloadTitle);
                payloadArea = new JTextArea();
                optionPanel.add(payloadTitlePanel);
                optionPanel.add(payloadArea);

                JPanel delayPanel = new JPanel();
                JLabel delayBetweenEachRequest = new JLabel("Delay Between Each Request in ms (0 = no limit): ");
                msBetweenEachRequest = new JTextField("10",10);
                delayPanel.add(delayBetweenEachRequest);
                delayPanel.add(msBetweenEachRequest);
                optionPanel.add(delayPanel);

                tabbedPane.addTab("Log", splitPane);
                tabbedPane.addTab("Options", optionPanel);

                // Add View
                PayloadTester.this.callbacks.addSuiteTab(PayloadTester.this);
                
                // Load Settings
                String wordlist = PayloadTester.this.callbacks.loadExtensionSetting(WORDLIST_SETTING);
                if(wordlist != null && !wordlist.isEmpty()){
                    payloadArea.append(wordlist);
                }
            }
        });
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    public void checkVul(IHttpRequestResponse baseRequestResponse, int row){
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(baseRequestResponse);

        // Full url
        URL url = analyzeRequest.getUrl();

        String method = analyzeRequest.getMethod();
        byte content_type = analyzeRequest.getContentType();
        List<String> headers =  analyzeRequest.getHeaders();
        try{
            String payloadString = payloadArea.getText();
            String delayString = msBetweenEachRequest.getText();
            int delayMs = 10;
            try{
                delayMs = Integer.parseInt(delayString);
            }catch(Exception e){
                // Convert error
                e.printStackTrace();
            }
            if(!payloadString.isEmpty()) {
                String payloads[] = payloadString.split("\n");

                if(content_type == IRequestInfo.CONTENT_TYPE_JSON){
                    byte[] originalRequest = baseRequestResponse.getRequest();

                    String bodyString = new String(
                            Arrays.copyOfRange(originalRequest, analyzeRequest.getBodyOffset(), originalRequest.length));

                    stdout.println("Start scan");
                    Gson gson = new GsonBuilder().serializeNulls().setPrettyPrinting().create();
                    JsonElement je = JsonParser.parseString(bodyString);

                    loopAllFieldsForRequest(gson, baseRequestResponse, headers, url, je, je, payloads, delayMs);
                }else if(content_type == CONTENT_TYPE_URL_ENCODED || content_type == CONTENT_TYPE_NONE) {
                    for(IParameter parameter : analyzeRequest.getParameters()){
                        if(parameter.getType() == PARAM_URL) {
                            stdout.println(parameter.getName() + "/" + parameter.getValue());
                            for(String testPayload : payloads) {
                                byte[] updatedRequest = helpers.updateParameter(baseRequestResponse.getRequest(),
                                        helpers.buildParameter(parameter.getName(),testPayload,parameter.getType()));

                                // Fire the request
                                Thread.sleep(delayMs);
                                long startTime = System.currentTimeMillis();
                                IHttpRequestResponse resp = fireRequest(baseRequestResponse, updatedRequest);
                                if (resp != null) {
                                    long responseTime = System.currentTimeMillis() - startTime;
                                    LogEntry logEntry = new LogEntry(url, parameter.getName() + " -> " + testPayload, "" + this.helpers.analyzeResponse(resp.getResponse()).getStatusCode(), resp.getResponse().length, responseTime, resp);
                                    log.add(logEntry);
                                    fireTableDataChanged(); // Notify data change
                                }
                            }
                        }
                    }
                }else{
                    stdout.println("Request not supported, url: "+url+" , method: "+method+" , content type: "+content_type);
                    LogEntry logEntry = new LogEntry(url, "not supported", "not supported", -1, -1, baseRequestResponse);
                    log.set(row, logEntry);
                    fireTableRowsUpdated(row, row);
                }
            }else{
                LogEntry logEntry = new LogEntry(url, "No payload provided", "No payload provided", -1, -1, baseRequestResponse);
                log.set(row, logEntry);
                fireTableRowsUpdated(row, row);
            }
        }catch (Exception e){
            this.stdout.println(e);
            e.printStackTrace();
        }
    }

    void loopAllFieldsForRequest(Gson gson, IHttpRequestResponse baseRequestResponse, List<String> headers, URL url, JsonElement originalElement, JsonElement je, String payloads[], int delayMs) throws InterruptedException {
        for(Map.Entry<String, JsonElement> entry : je.getAsJsonObject().entrySet()) {
            stdout.println("Key = " + entry.getKey() + " Value = " + entry.getValue() );

            if(entry.getValue().isJsonObject()){
                stdout.println("IsJsonObject");
                loopAllFieldsForRequest(gson, baseRequestResponse, headers, url, originalElement, entry.getValue(), payloads, delayMs);
            }else if(entry.getValue().isJsonPrimitive()) {
                stdout.println("IsJsonPrimitive");
                // Copy the value
                for(String testPayload : payloads) {
                    JsonElement originalValue = entry.getValue().deepCopy();

                    IHttpRequestResponse resp = null;
                    // If it is string
                    if(!testPayload.equals("null")){
                        if (originalValue.getAsJsonPrimitive().isString()) {
                            // String processing
                            je.getAsJsonObject().add(entry.getKey(), new JsonPrimitive(testPayload));
                        }else{ // Other datatype ?
                            try {
                                je.getAsJsonObject().add(entry.getKey(), gson.fromJson(testPayload, JsonElement.class));
                            }catch(JsonSyntaxException e){
                                // Try string then
                                je.getAsJsonObject().add(entry.getKey(), new JsonPrimitive(testPayload));
                            }
                        }
                    }else{
                        // Null test
                        je.getAsJsonObject().add(entry.getKey(), null);
                    }

                    // Fire request
                    Thread.sleep(delayMs);
                    long startTime = System.currentTimeMillis();
                    resp = fireJsonRequest(gson, baseRequestResponse, headers, originalElement);

                    if (resp != null) {
                        long responseTime = System.currentTimeMillis() - startTime;
                        LogEntry logEntry = new LogEntry(url, entry.getKey() + " -> " + testPayload, "" + this.helpers.analyzeResponse(resp.getResponse()).getStatusCode(), resp.getResponse().length, responseTime, resp);
                        log.add(logEntry);
                        fireTableDataChanged(); // Notify data change
                    }

                    // Rollback
                    je.getAsJsonObject().add(entry.getKey(), originalValue);
                }
            }
        }
    }

    private IHttpRequestResponse fireJsonRequest(Gson gson, IHttpRequestResponse baseRequestResponse, List<String> headers, JsonElement payloadElement){
        // element to json string
        String stringJson = gson.toJson(payloadElement);
        // String to bytes
        byte[] requestBody = stringJson.getBytes();

        byte[] postMessage = this.helpers.buildHttpMessage(headers, requestBody);
        return fireRequest(baseRequestResponse, postMessage);
    }

    private IHttpRequestResponse fireRequest(IHttpRequestResponse baseRequestResponse, byte[] message){
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, message);
        return resp;
    }

    @Override
    public String getTabCaption() {
        return "Tester";
    }

    @Override
    public Component getUiComponent() {
        return tabbedPane;
    }

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 6;
    }

    @Override
    public String getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return ""+rowIndex;
            case 1:
                return logEntry.url.toString();
            case 2:
                return logEntry.payload;
            case 3:
                return logEntry.status;
            case 4:
                return ""+logEntry.responseSize;
            case 5:
                return ""+logEntry.responseTime;
            default:
                return "";
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:
                return "#";
            case 1:
                return "URL";
            case 2:
                return "Request Payload";
            case 3:
                return "Status";
            case 4:
                return "Response Size";
            case 5:
                return "Response Time (ms)";
            default:
                return "";
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList<>(1);
        IHttpRequestResponse responses[] = invocation.getSelectedMessages();
        JMenuItem menuItem = new JMenuItem("Send to Tester");
        menus.add(menuItem);
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int row = log.size();
                LogEntry logEntry = new LogEntry(helpers.analyzeRequest(responses[0]).getUrl(), "scanning", "", -1, -1, responses[0]);
                log.add(logEntry);
                fireTableRowsInserted(row, row);

                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        saveConfig();
                        checkVul(responses[0], row);
                    }
                });
                thread.start();
            }
        });
        return menus;
    }

    private void saveConfig(){
        // Save the wordlist
        this.callbacks.saveExtensionSetting(WORDLIST_SETTING, payloadArea.getText());
    }

    private static class LogEntry{
        final URL url;
        final String payload;
        final String status;
        final int responseSize;
        final long responseTime;
        final IHttpRequestResponse requestResponse;

        LogEntry(URL url, String payload, String status, int responseSize, long responseTime, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.payload = payload;
            this.status = status;
            this.responseSize = responseSize;
            this.responseTime = responseTime;
            this.requestResponse = requestResponse;
        }
    }

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }
}
