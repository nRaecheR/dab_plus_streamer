/*
 *    Copyright (C) 2018
 *    Matthias P. Braendli (matthias.braendli@mpb.li)
 *
 *    Copyright (C) 2017
 *    Albrecht Lohofener (albrechtloh@gmx.de)
 *
 *    This file is based on SDR-J
 *    Copyright (C) 2010, 2011, 2012
 *    Jan van Katwijk (J.vanKatwijk@gmail.com)
 *
 *    This file is part of the welle.io.
 *    Many of the ideas as implemented in welle.io are derived from
 *    other work, made available through the GNU general Public License.
 *    All copyrights of the original authors are recognized.
 *
 *    welle.io is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    welle.io is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with welle.io; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <set>
#include <utility>
#include <cstdio>
#include <unistd.h>
#ifdef HAVE_SOAPYSDR
#  include "soapy_sdr.h"
#endif
#include <rtl_tcp.h>
#include <rtl_sdr.h>
#include "server/webradiointerface.h"
#include "backend/radio-receiver.h"
#include "input/input_factory.h"
#include "various/channels.h"
#include "libs/json.hpp"
extern "C" {
#include "various/wavfile.h"
}

#ifdef GITDESCRIBE
#define VERSION GITDESCRIBE
#else
#define VERSION "unknown"
#endif

using namespace std;

using namespace nlohmann;

class WavProgrammeHandler: public ProgrammeHandlerInterface {
    public:
        WavProgrammeHandler(uint32_t SId, const std::string& fileprefix) :
            SId(SId),
            filePrefix(fileprefix) {}
        ~WavProgrammeHandler() {
            if (fd) {
                wavfile_close(fd);
            }
        }
        WavProgrammeHandler(const WavProgrammeHandler& other) = delete;
        WavProgrammeHandler& operator=(const WavProgrammeHandler& other) = delete;
        WavProgrammeHandler(WavProgrammeHandler&& other) = default;
        WavProgrammeHandler& operator=(WavProgrammeHandler&& other) = default;

        virtual void onFrameErrors(int frameErrors) override { (void)frameErrors; }
        virtual void onNewAudio(std::vector<int16_t>&& audioData, int sampleRate, const string& mode) override
        {
            if (rate != sampleRate ) {
                cout << "[0x" << std::hex << SId << std::dec << "] " <<
                    "rate " << sampleRate <<  " mode " << mode << endl;

                string filename = filePrefix + ".wav";
                if (fd) {
                    wavfile_close(fd);
                }
                fd = wavfile_open(filename.c_str(), sampleRate, 2);

                if (not fd) {
                    cerr << "Could not open wav file " << filename << endl;
                }
            }
            rate = sampleRate;

            if (fd) {
                wavfile_write(fd, audioData.data(), audioData.size());
            }
        }

        virtual void onRsErrors(bool uncorrectedErrors, int numCorrectedErrors) override {
            (void)uncorrectedErrors; (void)numCorrectedErrors; }
        virtual void onAacErrors(int aacErrors) override { (void)aacErrors; }
        virtual void onNewDynamicLabel(const std::string& label) override
        {
            cout << "[0x" << std::hex << SId << std::dec << "] " <<
                "DLS: " << label << endl;
        }

        virtual void onMOT(const mot_file_t& mot_file) override { (void)mot_file;}
        virtual void onPADLengthError(size_t announced_xpad_len, size_t xpad_len) override
        {
            cout << "X-PAD length mismatch, expected: " << announced_xpad_len << " got: " << xpad_len << endl;
        }

    private:
        uint32_t SId;
        string filePrefix;
        FILE* fd = nullptr;
        int rate = 0;
};


class RadioInterface : public RadioControllerInterface {
    public:
        virtual void onSNR(float /*snr*/) override { }
        virtual void onFrequencyCorrectorChange(int /*fine*/, int /*coarse*/) override { }
        virtual void onSyncChange(char isSync) override { synced = isSync; }
        virtual void onSignalPresence(bool /*isSignal*/) override { }
        virtual void onServiceDetected(uint32_t sId) override
        {
            cout << "New Service: 0x" << hex << sId << dec << endl;
        }

        virtual void onNewEnsemble(uint16_t eId) override
        {
            cout << "Ensemble name id: " << hex << eId << dec << endl;
        }

        virtual void onSetEnsembleLabel(DabLabel& label) override
        {
            cout << "Ensemble label: " << label.utf8_label() << endl;
        }

        virtual void onDateTimeUpdate(const dab_date_time_t& dateTime) override
        {
            json j;
            j["UTCTime"] = {
                {"year", dateTime.year},
                {"month", dateTime.month},
                {"day", dateTime.day},
                {"hour", dateTime.hour},
                {"minutes", dateTime.minutes},
                {"seconds", dateTime.seconds}
            };

            if (last_date_time != j) {
                cout << j << endl;
                last_date_time = j;
            }
        }

        virtual void onFIBDecodeSuccess(bool crcCheckOk, const uint8_t* fib) override {
            if (fic_fd) {
                if (not crcCheckOk) {
                    return;
                }

                // convert bitvector to byte vector
                vector<uint8_t> buf(32);
                for (size_t i = 0; i < buf.size(); i++) {
                    uint8_t v = 0;
                    for (int j = 0; j < 8; j++) {
                        if (fib[8*i+j]) {
                            v |= 1 << (7-j);
                        }
                    }
                    buf[i] = v;
                }

                fwrite(buf.data(), buf.size(), sizeof(buf[0]), fic_fd);
            }
        }
        virtual void onNewImpulseResponse(std::vector<float>&& data) override { (void)data; }
        virtual void onNewNullSymbol(std::vector<DSPCOMPLEX>&& data) override { (void)data; }
        virtual void onConstellationPoints(std::vector<DSPCOMPLEX>&& data) override { (void)data; }
        virtual void onMessage(message_level_t level, const std::string& text, const std::string& text2 = std::string()) override
        {
            std::string fullText;
            if (text2.empty())
                fullText = text;
            else
                fullText = text + text2;

            switch (level) {
                case message_level_t::Information:
                    cerr << "Info: " << fullText << endl;
                    break;
                case message_level_t::Error:
                    cerr << "Error: " << fullText << endl;
                    break;
            }
        }

        virtual void onTIIMeasurement(tii_measurement_t&& m) override
        {
            json j;
            j["TII"] = {
                {"comb", m.comb},
                {"pattern", m.pattern},
                {"delay", m.delay_samples},
                {"delay_km", m.getDelayKm()},
                {"error", m.error}
            };
            cout << j << endl;
        }

        json last_date_time;
        bool synced = false;
        FILE* fic_fd = nullptr;
};

struct options_t {
    string soapySDRDriverArgs = "";
    string antenna = "";
    int gain = -1;
    list<string> channels;
    string iqsource = "";
    string programme = "GRRIF";
    string frontend = "auto";
    string frontend_args = "";
    bool dump_programme = false;
    bool decode_all_programmes = false;
    string web_url = "";
    int web_port = 7979; // positive value means enable

    RadioReceiverOptions rro;
};

static void usage()
{
    cerr <<
    "Usage: dab_plus_streamer [OPTION]" << endl <<
    "   or: dab_plus_streamer -w <port> [OPTION]" << endl <<
    endl <<
    "Options:" << endl <<
    endl <<
    "Tuning:" << endl <<
    "    -c channel    Tune to <channel> (eg. 10B, 5A, LD...)." << endl <<
    "    -p programme  Tune to <programme> (text name of the radio: eg. GRIFF)." << endl <<
    endl <<
    "Dumping:" << endl <<
    "    -D            Dump FIC and all programmes to files (cannot be used with -C)." << endl <<
    "                  This generates: dump.fic; <programme_name.msc> files;" << endl <<
    "                  <programme_name.wav> files." << endl <<
    "    -d            Dump programme to <programme_name.msc> file." << endl <<
    endl <<
    "Web server mode:" << endl <<
    "    -w port       Enable web server on port <port>. Default: 7979" << endl <<
    "    -U url        The url where the dab plus server is accessible from." << endl <<
    "                  A hostname with the port should be given here, it will be used" << endl <<
    "                  as the prefix-URL for the M3U playlist." << endl <<
    "                  Example: -U http://localhost:8000" << endl <<
    endl <<
    "Backend and input options:" << endl <<
    "    -g gain       Set input gain to <gain> or -1 for auto gain." << endl <<
    "    -F driver     Set input driver and arguments." << endl <<
    "                  Please note that some input drivers are available only if" << endl <<
    "                  they were enabled at build time." << endl <<
    "                  Possible values are: auto (default), airspy, rtl_sdr," << endl <<
    "                  rtl_tcp, soapysdr." << endl <<
    "                  With \"rtl_tcp\", host IP and port can be specified as " << endl <<
    "                  \"rtl_tcp,<HOST_IP>:<PORT>\"." << endl <<
    "                  With \"rtl_sdr\", serial number of the device can be specified as " << endl <<
    "                  \"rtl_sdr,<serial-no>\"." << endl <<
    "    -s args       SoapySDR Driver arguments." << endl <<
    "    -A antenna    Set input antenna to ANT (for SoapySDR input only)." << endl <<
    "    -T            Enable TII decoding, increases CPU usage." << endl <<
    endl <<
    "Other options:" << endl <<
    "    -h            Display this help and exit." << endl <<
    "    -v            Output version information and exit." << endl <<
    endl <<
    "Examples:" << endl <<
    endl <<
    "dab_plus_streamer -c 10B -p GRRIF -F rtl_tcp,localhost:1234" << endl <<
    "    Receive 'GRRIF' on channel '10B' using 'rtl_tcp' driver on localhost:1234." << endl <<
    endl <<
    "dab_plus_streamer -c 10B -D " << endl <<
    "    Dump FIC and all programmes of channel 10B to files." << endl <<
    endl <<
    "dab_plus_streamer -c 10B -w 8000" << endl <<
    "    Enable web server on port 8000, decode programmes on channel 10B on demand" << endl <<
    "    (http://localhost:8000)." << endl <<
    endl <<
    "dab_plus_streamer -c 10B -Dw 8000" << endl <<
    "    Enable web server on port 8000, decode all programmes on channel 10B." << endl <<
    endl <<
    "Report bugs to: <https://github.com/nRaecheR/dab_plus_streamer/issues>" << endl;
}

static void copyright()
{
    cerr <<
    "Copyright (C) 2022 Arne Bockholdt." << endl <<
    "License GPL-2.0-or-later: GNU General Public License v2.0 or later" << endl <<
    "<https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html>" << endl <<
    endl <<
    "Written by: Arne Bockholdt" << endl <<
    "Other contributors: <https://github.com/nRaecheR/dab_plus_streamer/blob/master/AUTHORS>" << endl;
}

static void version()
{
    cerr << "dab_plus_streamer " << VERSION << endl;
}

options_t parse_cmdline(int argc, char **argv)
{
    options_t options;
    string fe_opt = "";
    string ch_opt = "";
    options.rro.decodeTII = false;

    int opt;
    while ((opt = getopt(argc, argv, "A:c:C:dDf:F:g:hp:Ps:Tt:uU:vw:")) != -1) {
        switch (opt) {
            case 'A':
                options.antenna = optarg;
                break;
            case 'c':
                ch_opt = optarg;
                break;
            case 'd':
                options.dump_programme = true;
                break;
            case 'D':
                options.decode_all_programmes = true;
                break;
            case 'f':
                options.iqsource = optarg;
                break;
            case 'F':
                fe_opt = optarg;
                break;
            case 'g':
                options.gain = std::atoi(optarg);
                break;
            case 'p':
                options.programme = optarg;
                break;
            case 'h':
                usage();
                exit(1);
            case 's':
                options.soapySDRDriverArgs = optarg;
                break;
            case 'T':
                options.rro.decodeTII = true;
                break;
            case 'v':
                version();
                cerr << endl;
                copyright();
                exit(0);
            case 'w':
                options.web_port = std::atoi(optarg);
                break;
			case 'U':
				options.web_url = optarg;
				break;
            case 'u':
                options.rro.disableCoarseCorrector = true;
                break;
            default:
                cerr << "Unknown option. Use -h for help" << endl;
                exit(1);
        }
    }

    if (!fe_opt.empty()) {
        size_t comma = fe_opt.find(',');
        if (comma != string::npos) {
            options.frontend      = fe_opt.substr(0,comma);
            options.frontend_args = fe_opt.substr(comma+1);
        } else {
            options.frontend = fe_opt;
        }
    }

    // Parse channel list
    while(!ch_opt.empty()) {
        size_t comma = ch_opt.find(',');
        if (comma != string::npos) {
            options.channels.push_back(ch_opt.substr(0,comma));
            ch_opt = ch_opt.substr(comma+1);
        } else {
            options.channels.push_back(ch_opt);
            ch_opt="";
        }
    }

    if(options.channels.empty()) {
        usage();
        exit(1);
    }

    return options;
}

int main(int argc, char **argv)
{
    auto options = parse_cmdline(argc, argv);
    version();

    RadioInterface ri;

    Channels channels;

    unique_ptr<CVirtualInput> in = nullptr;

    in.reset(CInputFactory::GetDevice(ri, options.frontend, options.frontend_args));

    if (not in) {
        cerr << "Could not start device" << endl;
        return 1;
    }
    
    if (options.gain == -1) {
        in->setAgc(true);
    }
    else {
        in->setGain(options.gain);
    }

#ifdef HAVE_SOAPYSDR
    if (not options.antenna.empty() and in->getID() == CDeviceID::SOAPYSDR) {
        dynamic_cast<CSoapySdr*>(in.get())->setDeviceParam(DeviceParam::SoapySDRAntenna, options.antenna);
    }

    if (not options.soapySDRDriverArgs.empty() and in->getID() == CDeviceID::SOAPYSDR) {
        dynamic_cast<CSoapySdr*>(in.get())->setDeviceParam(DeviceParam::SoapySDRDriverArgs, options.soapySDRDriverArgs);
    }
#endif
    if (options.frontend == "rtl_tcp" && !options.frontend_args.empty()) {
        string args = options.frontend_args;
        size_t colon = args.find(':');
        if (colon == string::npos) {
            cerr << "I need a colon ':' to parse rtl_tcp options!" << endl;
            return 1;
        }
        else {
            string host = args.substr(0, colon);
            string port = args.substr(colon + 1);
            if (!host.empty()) {
                dynamic_cast<CRTL_TCP_Client*>(in.get())->setServerAddress(host);
            }
            if (!port.empty()) {
                dynamic_cast<CRTL_TCP_Client*>(in.get())->setPort(atoi(port.c_str()));
            }
            // cout << "setting rtl_tcp host to '" << host << "', port to '" << atoi(port.c_str()) << "'" << endl;
        }
    }

    list<struct channel_info> freqs;

    // Check given channel list for valid IDs/frequencies
    for (const auto& channel: options.channels) {

        struct channel_info info;

        info.name = channel;
        info.frequency = channels.getFrequency(channel);
        if(0 == info.frequency) {
            cerr << "Invalid channel ID given" << endl;
            return 1;
        }

        freqs.push_back(info);

        cout << "ARG: Channel=" << info.name << ", Frequency=" << info.frequency << endl;
    }

    if (options.web_port != -1) {
        using DS = WebRadioInterface::DecodeStrategy;
        WebRadioInterface::DecodeSettings ds;
        if (options.decode_all_programmes) {
            ds.strategy = DS::All;
        }

        WebRadioInterface wri(*in, options.web_port, options.web_url, ds, options.rro);

        // Perform scan of channels for services
        wri.scan(freqs);

        // Start webserver
        wri.serve();
    }
    else {

        // Tune to first channel
        auto it = freqs.begin();

        auto info = *it;
        in->setFrequency(info.frequency);

        string service_to_tune = options.programme;

        RadioReceiver rx(ri, *in, options.rro);
        if (options.decode_all_programmes) {
            FILE* fic_fd = fopen("dump.fic", "w");

            if (fic_fd) {
                ri.fic_fd = fic_fd;
            }
        }

        rx.restart(false);

        cerr << "Wait for sync" << endl;
        while (not ri.synced) {
            this_thread::sleep_for(chrono::seconds(3));
        }

        cerr << "Wait for service list" << endl;
        while (rx.getServiceList().empty()) {
            this_thread::sleep_for(chrono::seconds(1));
        }

        // Wait an additional 3 seconds so that the receiver can complete the service list
        this_thread::sleep_for(chrono::seconds(3));

        if (options.decode_all_programmes) {
            using SId_t = uint32_t;
            map<SId_t, WavProgrammeHandler> phs;

            cerr << "Service list" << endl;
            for (const auto& s : rx.getServiceList()) {
                cerr << "  [0x" << std::hex << s.serviceId << std::dec << "] " <<
                    s.serviceLabel.utf8_label() << " ";
                for (const auto& sc : rx.getComponents(s)) {
                    cerr << " [component "  << sc.componentNr <<
                        " ASCTy: " <<
                        (sc.audioType() == AudioServiceComponentType::DAB ? "DAB" :
                         sc.audioType() == AudioServiceComponentType::DABPlus ? "DAB+" : "unknown") << " ]";

                    const auto& sub = rx.getSubchannel(sc);
                    cerr << " [subch " << sub.subChId << " bitrate:" << sub.bitrate() << " at SAd:" << sub.startAddr << "]";
                }
                cerr << endl;

                string dumpFilePrefix = s.serviceLabel.utf8_label();
                dumpFilePrefix.erase(std::find_if(dumpFilePrefix.rbegin(), dumpFilePrefix.rend(),
                            [](int ch) { return !std::isspace(ch); }).base(), dumpFilePrefix.end());

                WavProgrammeHandler ph(s.serviceId, dumpFilePrefix);
                phs.emplace(std::make_pair(s.serviceId, move(ph)));

                auto dumpFileName = dumpFilePrefix + ".msc";

                if (rx.addServiceToDecode(phs.at(s.serviceId), dumpFileName, s) == false) {
                    cerr << "Tune to " << service_to_tune << " failed" << endl;
                }
            }

            while (true) {
                cerr << "**** Enter '.' to quit." << endl;
                cin >> service_to_tune;
                if (service_to_tune == ".") {
                    break;
                }
            }
        }
    }

    if (ri.fic_fd) {
        FILE* fd = ri.fic_fd;
        ri.fic_fd = nullptr;
        fclose(fd);
    }

    return 0;
}
