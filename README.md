# Burp Payload Tester Extension
An automatic test to repeat the same method with different json or url fields one by one with wordlist.

### Supported format
- JSON
- UrlEncoded

# Downloads
Please check on [Releases](https://github.com/sebastian93921/burp-payload-tester/releases) page.

# How it works
First place any payloads into Options page
![image](https://user-images.githubusercontent.com/4918219/148170301-8107895e-c8f7-4d38-9232-0221da596eef.png)

Click on any Repeater request view, right click `Extensions` -> `PayloadTester` -> `Send To Tester`
![image](https://user-images.githubusercontent.com/4918219/148172582-ca85ad43-8055-447f-9950-ac3abe242ff4.png)

In `Tester` section you will now see the extension tested on every single field with response status
![image](https://user-images.githubusercontent.com/4918219/148172000-234c53f4-ff07-4cea-8d0c-bfaf08b190f0.png)

Right click `Clear history` to cleanup the table
![image](https://user-images.githubusercontent.com/4918219/148172650-f66ebf4f-5a1f-4365-916c-7e5d10e9575e.png)

# Loading Instructions
1. Launch BurpSuite
2. Go to the Extender tab and open the Extensions tab
3. Click on `Add`. In the dialog window, select `java` as Extension Type
4. Select the extension file `burp-payload-tester-X.X-packed.jar`

For further details about BurpSuite extensions, refer to their [documentation](https://portswigger.net/burp/help/extender.html#loading).

# Building Instructions
In Intellij, click on `Gradle` -> `burp-payload-tester` -> `Task` -> `other` -> `packjar` to compile and pack the extension into jar file
