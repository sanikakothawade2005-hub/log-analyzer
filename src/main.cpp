#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <map>

using namespace std;

ofstream report;

void writeReport(const string &text)
{
    cout << text;
    report << text;
}

void analyzeApacheAccessLog(const string &filePath)
{
    ifstream file(filePath);

    if (!file.is_open())
    {
        writeReport("Error: Could not open " + filePath + "\n");
        return;
    }

    string line;
    int totalRequests = 0;
    int totalHttpErrors = 0;
    int skippedLines = 0;

    map<string, int> statusCounts;
    map<string, int> ipCounts;

    while (getline(file, line))
    {
        size_t firstSpace = line.find(' ');
        size_t firstQuote = line.find('"');
        size_t secondQuote = line.find('"', firstQuote + 1);

        if (firstSpace != string::npos &&
            firstQuote != string::npos &&
            secondQuote != string::npos)
        {

            string ip = line.substr(0, firstSpace);

            string remaining = line.substr(secondQuote + 1);
            stringstream ss(remaining);

            string status;
            ss >> status;

            if (!status.empty())
            {
                totalRequests++;
                statusCounts[status]++;
                ipCounts[ip]++;

                if (status[0] == '4' || status[0] == '5')
                {
                    totalHttpErrors++;
                }
            }
            else
            {
                skippedLines++;
            }
        }
        else
        {
            skippedLines++;
        }
    }

    file.close();

    string mostCommonStatus;
    int highestStatusCount = 0;

    for (const auto &entry : statusCounts)
    {
        if (entry.second > highestStatusCount)
        {
            highestStatusCount = entry.second;
            mostCommonStatus = entry.first;
        }
    }

    string mostActiveIP;
    int highestIPCount = 0;

    for (const auto &entry : ipCounts)
    {
        if (entry.second > highestIPCount)
        {
            highestIPCount = entry.second;
            mostActiveIP = entry.first;
        }
    }

    writeReport("\n======================================\n");
    writeReport("APACHE ACCESS LOG STATISTICS\n");
    writeReport("======================================\n");
    writeReport("Total Requests: " + to_string(totalRequests) + "\n");
    writeReport("Total HTTP Errors: " + to_string(totalHttpErrors) + "\n");
    writeReport("Skipped Lines: " + to_string(skippedLines) + "\n");
    writeReport("Most Common Status: " + mostCommonStatus +
                " (" + to_string(highestStatusCount) + ")\n");
    writeReport("Most Active IP: " + mostActiveIP +
                " (" + to_string(highestIPCount) + " requests)\n");
}

void analyzeApacheErrorLog(const string &filePath)
{
    ifstream file(filePath);

    if (!file.is_open())
    {
        writeReport("Error: Could not open " + filePath + "\n");
        return;
    }

    string line;

    int totalErrors = 0;
    int skippedLines = 0;

    map<string, int> levelCounts;
    map<string, int> messageCounts;

    while (getline(file, line))
    {
        size_t firstBracket = line.find(']');

        if (firstBracket == string::npos)
        {
            skippedLines++;
            continue;
        }

        size_t levelStart = line.find('[', firstBracket + 1);
        size_t levelEnd = line.find(']', levelStart + 1);

        if (levelStart != string::npos &&
            levelEnd != string::npos)
        {

            string level = line.substr(
                levelStart + 1,
                levelEnd - levelStart - 1);

            string message = line.substr(levelEnd + 1);

            if (!message.empty() && message[0] == ' ')
            {
                message.erase(0, 1);
            }

            totalErrors++;
            levelCounts[level]++;
            messageCounts[message]++;
        }
        else
        {
            skippedLines++;
        }
    }

    file.close();

    string mostCommonLevel;
    int highestLevelCount = 0;

    for (const auto &entry : levelCounts)
    {
        if (entry.second > highestLevelCount)
        {
            highestLevelCount = entry.second;
            mostCommonLevel = entry.first;
        }
    }

    string mostCommonMessage;
    int highestMessageCount = 0;

    for (const auto &entry : messageCounts)
    {
        if (entry.second > highestMessageCount)
        {
            highestMessageCount = entry.second;
            mostCommonMessage = entry.first;
        }
    }

    writeReport("\n======================================\n");
    writeReport("APACHE ERROR LOG STATISTICS\n");
    writeReport("======================================\n");
    writeReport("Total Log Entries: " + to_string(totalErrors) + "\n");
    writeReport("Skipped Lines: " + to_string(skippedLines) + "\n");
    writeReport("Most Common Error Level: " + mostCommonLevel +
                " (" + to_string(highestLevelCount) + ")\n");
    writeReport("Most Repeated Message: " + mostCommonMessage +
                " (" + to_string(highestMessageCount) +
                " occurrences)\n");
}

void analyzeOpenSSHLog(const string &filePath)
{
    ifstream file(filePath);

    if (!file.is_open())
    {
        writeReport("Error: Could not open " + filePath + "\n");
        return;
    }

    string line;

    int totalEvents = 0;
    int failedEvents = 0;
    int successfulEvents = 0;

    const int suspiciousThreshold = 5;

    map<string, int> failedIPCounts;
    map<string, int> successfulIPCounts;

    while (getline(file, line))
    {
        totalEvents++;

        bool failed = false;
        bool successful = false;

        if (line.find("Failed password") != string::npos ||
            line.find("authentication failure") != string::npos ||
            line.find("Invalid user") != string::npos)
        {

            failed = true;
            failedEvents++;
        }

        if (line.find("Accepted password") != string::npos ||
            line.find("Accepted publickey") != string::npos)
        {

            successful = true;
            successfulEvents++;
        }

        size_t fromPosition = line.find("from ");

        if (fromPosition != string::npos)
        {
            stringstream ss(line.substr(fromPosition + 5));

            string ip;
            ss >> ip;

            if (!ip.empty())
            {
                if (failed)
                {
                    failedIPCounts[ip]++;
                }

                if (successful)
                {
                    successfulIPCounts[ip]++;
                }
            }
        }
    }

    file.close();

    string mostFailedIP;
    int highestFailedCount = 0;

    for (const auto &entry : failedIPCounts)
    {
        if (entry.second > highestFailedCount)
        {
            highestFailedCount = entry.second;
            mostFailedIP = entry.first;
        }
    }

    string mostSuccessfulIP;
    int highestSuccessfulCount = 0;

    for (const auto &entry : successfulIPCounts)
    {
        if (entry.second > highestSuccessfulCount)
        {
            highestSuccessfulCount = entry.second;
            mostSuccessfulIP = entry.first;
        }
    }

    writeReport("\n======================================\n");
    writeReport("OPENSSH LOG STATISTICS\n");
    writeReport("======================================\n");
    writeReport("Total Events: " + to_string(totalEvents) + "\n");
    writeReport("Failed Authentication Events: " +
                to_string(failedEvents) + "\n");

    writeReport("Successful Authentication Events: " +
                to_string(successfulEvents) + "\n");

    writeReport("IP With Most Failed Events: " +
                mostFailedIP + " (" +
                to_string(highestFailedCount) + ")\n");

    writeReport("IP With Most Successful Events: " +
                mostSuccessfulIP + " (" +
                to_string(highestSuccessfulCount) + ")\n");

    writeReport("\nSECURITY SUMMARY\n");
    writeReport("--------------------------------------\n");

    if (highestFailedCount >= suspiciousThreshold)
    {
        writeReport("Suspicious authentication activity detected.\n");
    }
    else
    {
        writeReport("No high-frequency authentication activity detected.\n");
    }
}

int main()
{
    report.open("output/log_analysis_report.txt");

    if (!report.is_open())
    {
        cout << "Error: Could not create report file." << endl;
        return 1;
    }

    writeReport("======================================\n");
    writeReport("           LOG ANALYSIS REPORT\n");
    writeReport("======================================\n");

    // NOTE: These files come from the Rootly AI Labs dataset and are not included in this repo.
    // See "Dataset Setup" in README.md.
    analyzeApacheAccessLog("data/apache_access.log");
    analyzeApacheErrorLog("data/apache_error.log");
    analyzeOpenSSHLog("data/openssh.log");

    report.close();

    cout << "\nReport saved to output/log_analysis_report.txt"
         << endl;

    return 0;
}