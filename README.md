# Burp Payload Tester Extension
An automatic repeater to test each fields with payloads

# Downloads
Please check on [Releases](https://github.com/hhh/releases) page.

# How it works
First place any payloads into Options page
![image](https://user-images.githubusercontent.com/4918219/148170301-8107895e-c8f7-4d38-9232-0221da596eef.png)

Click on any Repeater request view, right click `Extensions` -> `PayloadTester` -> `Send To Tester`
![image](https://user-images.githubusercontent.com/4918219/148171892-4a6d6f3c-414a-472f-91a1-fceb8fbb6b96.png)

In `Tester` section you will now see the extension tested on every single field with response status
![image](https://user-images.githubusercontent.com/4918219/148172000-234c53f4-ff07-4cea-8d0c-bfaf08b190f0.png)

Right click `Clear history` to cleanup the table
![image](https://user-images.githubusercontent.com/4918219/148172280-e239d331-1498-43e1-b8f8-ea8af51350a7.png)

# Loading Instructions
1. Launch BurpSuite
2. Go to the Extender tab and open the Extensions tab
3. Click on `Add`. In the dialog window, select `java` as Extension Type
4. Select the extension file `burp-payload-tester-X.X-packed.jar`

For further details about BurpSuite extensions, refer to their [documentation](https://portswigger.net/burp/help/extender.html#loading).

# Building Instructions
In Intellij, click on `Gradle` -> `burp-payload-tester` -> `Task` -> `other` -> `packjar` to compile and pack the extension into jar file
