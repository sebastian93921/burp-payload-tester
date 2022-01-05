# Burp Payload Tester Extension
An automatic repeater to test each fields with payloads

# Downloads
Please check on [Releases](https://github.com/hhh/releases) page.

# How it works
First place any payloads into Options page

Click on any Repeater request view, right click `Extensions` -> `PayloadTester` -> `Send To Tester`

In `Tester` section you will now see the extension tested on every single field with response status

Right click `Clear history` to cleanup the table

# Loading Instructions
1. Launch BurpSuite
2. Go to the Extender tab and open the Extensions tab
3. Click on `Add`. In the dialog window, select `java` as Extension Type
4. Select the extension file `burp-payload-tester-X.X-packed.jar`

For further details about BurpSuite extensions, refer to their [documentation](https://portswigger.net/burp/help/extender.html#loading).

# Building Instructions
In Intellij, click on `Gradle` -> `burp-payload-tester` -> `Task` -> `other` -> `packjar` to compile and pack the extension into jar file
