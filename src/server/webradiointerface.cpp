/*
 *    Copyright (C) 2020
 *    Matthias P. Braendli (matthias.braendli@mpb.li)
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
#include <cmath>
#include <complex>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <errno.h>
#include <future>
#include <iomanip>
#include <iostream>
#include <regex>
#include <signal.h>
#include <stdexcept>
#include <sys/socket.h>
#include <utility>

#include "webradiointerface.h"
#include "Socket.h"
#include "channels.h"
#include "ofdm-decoder.h"
#include "radio-receiver.h"
#include "virtual_input.h"
#include "server/jsonconvert.h"
#include "server/webprogrammehandler.h"

#ifdef __unix__
# include <unistd.h>
# if _POSIX_VERSION >= 200809L
#  define HAVE_SIGACTION 1
#  include <signal.h>
# else
#  define HAVE_SIGACTION 0
# endif
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef GITDESCRIBE
#define VERSION GITDESCRIBE
#else
#define VERSION "unknown"
#endif

#define ASSERT_RX if (not rx) throw logic_error("rx does not exist")

constexpr size_t MAX_PENDING_MESSAGES = 512;

using namespace std;

static const char* http_ok = "HTTP/1.0 200 OK\r\n";
static const char* http_400 = "HTTP/1.0 400 Bad Request\r\n";
static const char* http_404 = "HTTP/1.0 404 Not Found\r\n";
static const char* http_405 = "HTTP/1.0 405 Method Not Allowed\r\n";
static const char* http_500 = "HTTP/1.0 500 Internal Server Error\r\n";
static const char* http_503 = "HTTP/1.0 503 Service Unavailable\r\n";
static const char* http_contenttype_mp3 = "Content-Type: audio/mpeg\r\n";
static const char* http_contenttype_m3u = "Content-Type: application/mpegurl\r\n";
static const char* http_contenttype_text = "Content-Type: text/plain\r\n";

static const char* http_contenttype_json =
        "Content-Type: application/json; charset=utf-8\r\n";

static const char* http_contenttype_js =
        "Content-Type: text/javascript; charset=utf-8\r\n";

static const char* http_contenttype_html =
        "Content-Type: text/html; charset=utf-8\r\n";

static const char* http_nocache = "Cache-Control: no-cache\r\n";

static string to_hex(uint32_t value, int width)
{
    std::stringstream sidstream;
    sidstream << "0x" <<
        std::setfill('0') << std::setw(width) <<
        std::hex << value;
    return sidstream.str();
}

static bool send_http_response(Socket& s, const string& statuscode,
        const string& data, const string& content_type = http_contenttype_text) {
    string headers = statuscode;
    headers += content_type;
    headers += http_nocache;
    headers += "\r\n";
    headers += data;
    ssize_t ret = s.send(headers.data(), headers.size(), MSG_NOSIGNAL);
    if (ret == -1) {
        cerr << "Failed to send response " << statuscode << " " << data << endl;
    }
    return ret != -1;
}

WebRadioInterface::WebRadioInterface(CVirtualInput& in,
        int port,
        string url,
        DecodeSettings ds,
        RadioReceiverOptions rro) :
    dabparams(1),
    input(in),
    spectrum_fft_handler(dabparams.T_u),
    rro(rro),
    decode_settings(ds),
    serverUrl(url)
{
    {
        // Ensure that rx always exists when rx_mut is free!
        lock_guard<mutex> lock(rx_mut);

        bool success = serverSocket.bind(port);
        if (success) {
            success = serverSocket.listen();
        }

        if (success) {
            rx = make_unique<RadioReceiver>(*this, in, rro);
        }

        if (not rx) {
            throw runtime_error("Could not initialise WebRadioInterface");
        }

        time_rx_created = chrono::system_clock::now();
        rx->restart(false);
    }

    programme_handler_thread = thread(&WebRadioInterface::handle_phs, this);
}

WebRadioInterface::~WebRadioInterface()
{
    running = false;
    if (programme_handler_thread.joinable()) {
        programme_handler_thread.join();
    }

    {
        lock_guard<mutex> lock(rx_mut);
        rx.reset();
    }
}

class TuneFailed {};

void WebRadioInterface::check_decoders_required()
{
    lock_guard<mutex> lock(rx_mut);
    ASSERT_RX;

    try {
        for (auto& s : rx->getServiceList()) {
            const auto sid = s.serviceId;

            try {
                const bool require =
                    rx->serviceHasAudioComponent(s) and
                    (decode_settings.strategy == DecodeStrategy::All or
                     phs.at(sid).needsToBeDecoded());
                const bool is_decoded = programmes_being_decoded[sid];

                if (require and not is_decoded) {
                    bool success = rx->addServiceToDecode(phs.at(sid), "", s);

                    if (success) {
                        programmes_being_decoded[sid] = success;
                    }
                    else {
                        throw TuneFailed();
                    }
                }
                else if (is_decoded and not require) {
                    bool success = rx->removeServiceToDecode(s);

                    if (success) {
                        programmes_being_decoded[sid] = false;
                    }
                    else {
                        cerr << "Stop playing 0x" << to_hex(s.serviceId, 4) <<
                            " failed" << endl;
                        throw TuneFailed();
                    }
                }
            }
            catch (const out_of_range&) {
                cerr << "Cannot tune to 0x" << to_hex(s.serviceId, 4) <<
                    " because no handler exists!" << endl;
            }
        }
    }
    catch (const TuneFailed&) {
        rx->restart_decoder();
        phs.clear();
        programmes_being_decoded.clear();
    }
    phs_changed.notify_all();
}

void WebRadioInterface::retune(const std::string& channel)
{
    // Ensure two closely occurring retune() calls don't get stuck
    unique_lock<mutex> retune_lock(retune_mut);

    auto freq = channels.getFrequency(channel);
    if (freq == 0) {
        cerr << "RETUNE Invalid channel: " << channel << endl;
        return;
    }

    cerr << "RETUNE: Retune to " << freq << endl;

    running = false;
    if (programme_handler_thread.joinable()) {
        programme_handler_thread.join();
    }

    cerr << "RETUNE Take ownership of RX" << endl;
    {
        unique_lock<mutex> lock(rx_mut);
        // Even though it would be ok for rx to be inexistent here,
        // we check to uncover errors.
        ASSERT_RX;

        cerr << "RETUNE Keep RX, don't destroy" << endl;
        //rx.reset();

        {
            lock_guard<mutex> data_lock(data_mut);
            last_dateTime = {};
            last_snr = 0;
            last_fine_correction = 0;
            last_coarse_correction = 0;
        }

        synced = false;

        {
            lock_guard<mutex> fib_lock(fib_mut);
            num_fic_crc_errors = 0;
        }
        tiis.clear();

        struct channel_info info;

        info.name = channel;
        info.frequency = freq;

        rx->setChannelInfo(info);
        cerr << "RETUNE Set frequency" << endl;
        input.setFrequency(freq);
        input.reset(); // Clear buffer

        cerr << "RETUNE Restart RX" << endl;
        //rx = make_unique<RadioReceiver>(*this, input, rro);
        if (not rx) {
            throw runtime_error("Could not initialise RadioReceiver");
        }

        //time_rx_created = chrono::system_clock::now();
        rx->restart(false);

        cerr << "RETUNE Start programme handler" << endl;
        running = true;
        programme_handler_thread = thread(&WebRadioInterface::handle_phs, this);
    }
}

void WebRadioInterface::scan(std::list<struct channel_info>& channel_infos){

    cerr << "SCAN: Begin scanning channels" << endl;

    cerr << "SCAN Take ownership of RX" << endl;
    {
        cerr << "SCAN Keep RX, don't destroy" << endl;

        // Tune to all given channels and scan for services
        for (auto& info : channel_infos) {

            cerr << "SCAN Wait for PHT" << endl;
            running = false;
            if (programme_handler_thread.joinable()) {
                programme_handler_thread.join();
            }
            {
            unique_lock<mutex> lock(rx_mut);

                // Even though it would be ok for rx to be inexistent here,
                // we check to uncover errors.
                ASSERT_RX;

                cerr << "SCAN data_lock" << endl;
                {
                    lock_guard<mutex> data_lock(data_mut);
                    last_dateTime = {};
                    last_snr = 0;
                    last_fine_correction = 0;
                    last_coarse_correction = 0;
                }

                cerr << "SCAN sync=false" << endl;

                synced = false;

                cerr << "SCAN fib_lock" << endl;
                {
                    lock_guard<mutex> fib_lock(fib_mut);
                    num_fic_crc_errors = 0;
                }
                cerr << "SCAN tiis.clear" << endl;
                tiis.clear();

                cerr << "SCAN setChannel" << endl;
                rx->setChannelInfo(info);
                cerr << "SCAN Set frequency for channel " << info.name << endl;
                input.setFrequency(info.frequency);

                cerr << "SCAN Input Reset" << endl;
                input.reset(); // Clear buffer

                //TODO: Replace it with a non-modified function
                cerr << "SCAN RX Restart" << endl;
                rx->restart(false);
            }

            cerr << "SCAN Start programme handler" << endl;
            running = true;
            programme_handler_thread = thread(&WebRadioInterface::handle_phs, this);

            this_thread::sleep_for(chrono::seconds(5));
        }
    }
}

static string recv_line(Socket& s) {
    string line;
    bool cr_seen = false;

    while (true) {
        char c = 0;
        ssize_t ret = s.recv(&c, 1, 0);
        if (ret == 0) {
            return "";
        }
        else if (ret == -1) {
            string errstr = strerror(errno);
            cerr << "recv error " << errstr << endl;
            return "";
        }

        line += c;

        if (c == '\r') {
            cr_seen = true;
        }
        else if (cr_seen and c == '\n') {
            return line;
        }
    }
}

static vector<char> recv_exactly(Socket& s, size_t num_bytes)
{
    vector<char> buf(num_bytes);
    size_t rx = 0;

    while (rx < num_bytes) {
        const size_t remain = num_bytes - rx;
        ssize_t ret = s.recv(buf.data() + rx, remain, 0);

        if (ret == 0) {
            break;
        }
        else if (ret == -1) {
            string errstr = strerror(errno);
            cerr << "recv error " << errstr << endl;
            return {};
        }
        else {
            rx += ret;
        }
    }

    return buf;
}

static vector<string> split(const string& str, char c = ' ')
{
    const char *s = str.data();
    vector<string> result;
    do {
        const char *begin = s;
        while (*s != c && *s)
            s++;
        result.push_back(string(begin, s));
    } while (0 != *s++);
    return result;
}

struct http_request_t {
    bool valid = false;

    bool is_get = false;
    bool is_post = false;
    string url;
    map<string, string> headers;
    string post_data;
};


static http_request_t parse_http_headers(Socket& s) {
    http_request_t r;

    const auto first_line = recv_line(s);
    const auto request_type = split(first_line);

    if (request_type.size() != 3) {
        cerr << "Malformed request: " << first_line << endl;
        return r;
    }
    else if (request_type[0] == "GET") {
        r.is_get = true;
    }
    else if (request_type[0] == "POST") {
        r.is_post = true;
    }
    else {
        return r;
    }

    r.url = request_type[1];

    while (true) {
        string header_line = recv_line(s);

        if (header_line == "\r\n") {
            break;
        }

        const auto header = split(header_line, ':');

        if (header.size() == 2) {
            r.headers.emplace(header[0], header[1]);
        }
    }

    if (r.is_post) {
        constexpr auto CL = "Content-Length";
        if (r.headers.count(CL) == 1) {
            try {
                const int content_length = std::stoi(r.headers[CL]);
                if (content_length > 1024 * 1024) {
                    cerr << "Unreasonable POST Content-Length: " << content_length << endl;
                    return r;
                }

                const auto buf = recv_exactly(s, content_length);
                r.post_data = string(buf.begin(), buf.end());
            }
            catch (const invalid_argument&) {
                cerr << "Cannot parse POST Content-Length: " << r.headers[CL] << endl;
                return r;
            }
            catch (const out_of_range&) {
                cerr << "Cannot represent POST Content-Length: " << r.headers[CL] << endl;
                return r;
            }
        }
    }

    r.valid = true;
    return r;
}

bool WebRadioInterface::dispatch_client(Socket&& client)
{
    Socket s(move(client));

    bool success = false;

    if (not s.valid()) {
        cerr << "socket in dispatcher not valid!" << endl;
        return false;
    }

    const auto req = parse_http_headers(s);

    if (not req.valid) {
        return false;
    }
    else {
        if (req.is_get) {
            if (req.url == "/") {
                success = send_file(s, "index.html", http_contenttype_html);
            }
            else if (req.url == "/index.js") {
                success = send_file(s, "index.js", http_contenttype_js);
            }
            else if (req.url == "/mux.json") {
                success = send_mux_json(s);
            }
            else if (req.url == "/streams.m3u") {
                success = send_mux_playlist(s);
            }
            else if (req.url == "/channel") {
                success = send_channel(s);
            }
            else if (req.url == "/fftwindowplacement" or req.url == "/enablecoarsecorrector") {
                send_http_response(s, http_405,
                        "405 Method Not Allowed\r\n" + req.url + " is POST-only");
                return false;
            }
            else {
                const regex regex_slide(R"(^[/]slide[/]([^ ]+))");
                std::smatch match_slide;

                const regex regex_mp3(R"(^[/]mp3[/]([^ ]+))");
                std::smatch match_mp3;
                if (regex_search(req.url, match_mp3, regex_mp3)) {

                    std::stringstream channel_path (match_mp3[1]);
                    std::string ch, sid;

                    std::getline(channel_path, ch , '/');
                    std::getline(channel_path, sid , '/');

                    cout << "WEB: Requested channel=" << ch << ", sid=" << sid << endl;

                    if(!ch.empty() && !sid.empty())
                        success = send_mp3(s, ch, sid);
                }
                else if (regex_search(req.url, match_slide, regex_slide)) {
                    success = send_slide(s, match_slide[1]);
                }
                else {
                    cerr << "Could not understand GET request " << req.url << endl;
                }
            }
        }
        else if (req.is_post) {
            if (req.url == "/channel") {
                success = handle_channel_post(s, req.post_data);
            }
            else if (req.url == "/fftwindowplacement") {
                success = handle_fft_window_placement_post(s, req.post_data);
            }
            else if (req.url == "/enablecoarsecorrector") {
                success = handle_coarse_corrector_post(s, req.post_data);
            }
            else {
                cerr << "Could not understand POST request " << req.url << endl;
            }
        }
        else {
            throw logic_error("valid req is neither GET nor POST!");
        }

        if (not success) {
            send_http_response(s, http_404, "Could not understand request.\r\n");
        }

        return success;
    }
}

bool WebRadioInterface::send_file(Socket& s,
        const std::string& filename,
        const std::string& content_type)
{
    FILE *fd = fopen(filename.c_str(), "r");
    if (fd) {
        if (not send_http_response(s, http_ok, "", content_type)) {
            cerr << "Failed to send file headers" << endl;
            fclose(fd);
            return false;
        }

        vector<char> data(1024);
        ssize_t ret = 0;
        do {
            ret = fread(data.data(), 1, data.size(), fd);
            ret = s.send(data.data(), ret, MSG_NOSIGNAL);
            if (ret == -1) {
                cerr << "Failed to send file data" << endl;
                fclose(fd);
                return false;
            }

        } while (ret > 0);

        fclose(fd);
        return true;
    }
    else {
        return send_http_response(s, http_500, "file '" + filename + "' is missing!");
    }
    return false;
}

bool WebRadioInterface::send_mux_json(Socket& s)
{
    MuxJson mux_json;

    mux_json.receiver.software.name = "dab_plus_streamer";
    mux_json.receiver.software.version = VERSION;
    mux_json.receiver.software.fftwindowplacement = fftPlacementMethodToString(rro.fftPlacementMethod);
    mux_json.receiver.software.coarsecorrectorenabled = not rro.disableCoarseCorrector;
    mux_json.receiver.software.freqsyncmethod = freqSyncMethodToString(rro.freqsyncMethod);
    mux_json.receiver.software.lastchannelchange = time_rx_created;
    mux_json.receiver.hardware.name = input.getDescription();
    mux_json.receiver.hardware.gain = input.getGain();

    {
        lock_guard<mutex> lock(fib_mut);
        mux_json.demodulator_fic_numcrcerrors = num_fic_crc_errors;
    }

    {
        lock_guard<mutex> lock(rx_mut);
        ASSERT_RX;

        mux_json.ensemble.label = rx->getEnsembleLabel();

        mux_json.ensemble.id = to_hex(rx->getEnsembleId(), 4);
        mux_json.ensemble.ecc = to_hex(rx->getEnsembleEcc(), 2);

        bool add_service = false;

        for (const auto& s : rx->getServiceList()) {
            ServiceJson service;
            service.sid = to_hex(s.serviceId, 4);
            service.channel = s.channel.name;
            service.frequency = s.channel.frequency;
            service.programType = s.programType;
            service.ptystring = DABConstants::getProgramTypeName(s.programType);
            service.language = s.language;
            service.languagestring = DABConstants::getLanguageName(s.language);
            service.label = s.serviceLabel;
            service.url_mp3 = "";

            for (const auto& sc : rx->getComponents(s)) {
                ComponentJson component;
                component.componentnr = sc.componentNr;
                component.primary = (sc.PS_flag ? true : false);
                component.caflag = (sc.CAflag ? true : false);
                component.label = sc.componentLabel;

                const auto sub = rx->getSubchannel(sc);

                switch (sc.transportMode()) {
                    case TransportMode::Audio:
                        component.transportmode = "audio";
                        component.ascty = make_unique<string>(
                                string{
                                    (sc.audioType() == AudioServiceComponentType::DAB ? "DAB" :
                                     sc.audioType() == AudioServiceComponentType::DABPlus ? "DAB+" :
                                     "unknown")});
                        if (sc.audioType() == AudioServiceComponentType::DAB or
                            sc.audioType() == AudioServiceComponentType::DABPlus) {
                            string urlmp3 = "/mp3/" + s.channel.name + "/" + to_hex(s.serviceId, 4);
                            service.url_mp3 = serverUrl + urlmp3;
                        }

                        add_service = true;

                        break;
                    case TransportMode::FIDC:
                        component.transportmode = "fidc";
                        component.dscty = make_unique<uint16_t>(sc.DSCTy);
                        break;
                    case TransportMode::PacketData:
                        component.transportmode = "packetdata";
                        component.scid = make_unique<uint16_t>(sc.SCId);
                        break;
                    case TransportMode::StreamData:
                        component.transportmode = "streamdata";
                        component.dscty = make_unique<uint16_t>(sc.DSCTy);
                        break;
                }

                component.subchannel = sub;

                service.components.push_back(move(component));
            }

            try {
                const auto& wph = phs.at(s.serviceId);
                const auto al = wph.getAudioLevels();
                service.audiolevel_present = true;
                service.audiolevel_time = chrono::system_clock::to_time_t(al.time);
                service.audiolevel_left = al.last_audioLevel_L;
                service.audiolevel_right = al.last_audioLevel_R;

                service.channels = 2;
                service.samplerate = wph.rate;
                service.mode = wph.mode;

                auto mot = wph.getMOT();
                service.mot_time = chrono::system_clock::to_time_t(mot.time);
                service.mot_lastchange = chrono::system_clock::to_time_t(mot.last_changed);

                auto dls = wph.getDLS();
                service.dls_label = dls.label;
                service.dls_time = chrono::system_clock::to_time_t(dls.time);
                service.dls_lastchange = chrono::system_clock::to_time_t(mot.last_changed);

                auto errorcounters = wph.getErrorCounters();
                service.errorcounters_frameerrors = errorcounters.num_frameErrors;
                service.errorcounters_rserrors = errorcounters.num_rsErrors;
                service.errorcounters_aacerrors = errorcounters.num_aacErrors;
                service.errorcounters_time = chrono::system_clock::to_time_t(dls.time);

                auto xpad_err = wph.getXPADErrors();
                service.xpaderror_haserror = xpad_err.has_error;
                if (xpad_err.has_error) {
                    service.xpaderror_announcedlen = xpad_err.announced_xpad_len;
                    service.xpaderror_len = xpad_err.xpad_len;
                    service.xpaderror_time = chrono::system_clock::to_time_t(xpad_err.time);
                }
            }
            catch (const out_of_range&) {
                service.audiolevel_present = false;
                service.channels = 0;
                service.samplerate = 0;
                service.mode = "invalid";
            }

            if(add_service)
                mux_json.services.push_back(move(service));
        }
    }

    {
        lock_guard<mutex> lock(data_mut);

        mux_json.utctime.year = last_dateTime.year;
        mux_json.utctime.month = last_dateTime.month;
        mux_json.utctime.day = last_dateTime.day;
        mux_json.utctime.hour = last_dateTime.hour;
        mux_json.utctime.minutes = last_dateTime.minutes;
        mux_json.utctime.lto = last_dateTime.hourOffset + ((double)last_dateTime.minuteOffset / 30.0);

        mux_json.demodulator_snr = last_snr;
        mux_json.demodulator_frequencycorrection = last_fine_correction + last_coarse_correction;
        mux_json.demodulator_timelastfct0frame = rx->getReceiverStats().timeLastFCT0Frame;
    }

    if (not send_http_response(s, http_ok, "", http_contenttype_json)) {
        return false;
    }

    const auto json_str = build_mux_json(mux_json);

    ssize_t ret = s.send(json_str.c_str(), json_str.size(), MSG_NOSIGNAL);
    if (ret == -1) {
        cerr << "Failed to send mux.json data" << endl;
        return false;
    }
    return true;
}

bool WebRadioInterface::send_mux_playlist(Socket& s)
{
    stringstream m3u;
    m3u << "#EXTM3U\n";

    {
        lock_guard<mutex> lock(rx_mut);
        ASSERT_RX;

        for (const auto& service : rx->getServiceList()) {
            auto hex_sid = to_hex(service.serviceId, 4);
            auto label = service.serviceLabel.utf8_label();
            string url_mp3 = "";

            for (const auto& servicecomponent : rx->getComponents(service)) {
                switch (servicecomponent.transportMode()) {
                    case TransportMode::Audio:
                        if (servicecomponent.audioType() == AudioServiceComponentType::DAB or
                            servicecomponent.audioType() == AudioServiceComponentType::DABPlus) {
                            url_mp3 = "/mp3/" + service.channel.name + "/" + hex_sid;
                        }
                        break;
                    default:
                        break;
                }
            }

            if (not url_mp3.empty()) {
                m3u << "#EXTINF:-1 sid=\"" << hex_sid << "\"," << label << "\n";
                m3u << serverUrl << url_mp3 << "\n";
            }
        }
    }

    if (not send_http_response(s, http_ok, "", http_contenttype_m3u)) {
        return false;
    }

    const auto m3u_str = m3u.str();
    ssize_t ret = s.send(m3u_str.c_str(), m3u_str.size(), MSG_NOSIGNAL);
    if (ret == -1) {
        cerr << "Failed to send streams.m3u data" << endl;
        return false;
    }
    return true;
}

bool WebRadioInterface::send_mp3(Socket& s, const std::string& channel, const std::string& stream)
{
    unique_lock<mutex> lock(rx_mut);
    ASSERT_RX;

    for (const auto& service : rx->getServiceList()) {
        if (rx->serviceHasAudioComponent(service) and
                (to_hex(service.serviceId, 4) == stream or
                (uint32_t)std::stoul(stream) == service.serviceId)) {
            try {
                auto& ph = phs.at(service.serviceId);

                lock.unlock();

                if (not send_http_response(s, http_ok, "", http_contenttype_mp3)) {
                    cerr << "Failed to send mp3 headers" << endl;
                    return false;
                }

                ProgrammeSender sender(move(s));

                cerr << "Registering mp3 sender" << endl;
                ph.registerSender(&sender);
                check_decoders_required();
                sender.wait_for_termination();

                cerr << "Removing mp3 sender" << endl;
                ph.removeSender(&sender);
                check_decoders_required();

                return true;
            }
            catch (const out_of_range& e) {
                cerr << "Could not setup mp3 sender for " <<
                    service.serviceId << ": " << e.what() << endl;

                send_http_response(s, http_503, e.what());
                return false;
            }
        }
    }
    return false;
}

bool WebRadioInterface::send_slide(Socket& s, const std::string& stream)
{
    for (const auto& wph : phs) {
        if (to_hex(wph.first, 4) == stream or
                (uint32_t)std::stoul(stream) == wph.first) {
            const auto mot = wph.second.getMOT();

            if (mot.data.empty()) {
                send_http_response(s, http_404, "404 Not Found\r\nSlide not available.\r\n");
                return true;
            }

            stringstream headers;
            headers << http_ok;

            headers << "Content-Type: ";
            switch (mot.subtype) {
                case MOTType::Unknown:
                    headers << "application/octet-stream";
                    break;
                case MOTType::JPEG:
                    headers << "image/jpeg";
                    break;
                case MOTType::PNG:
                    headers << "image/png";
                    break;
            }
            headers << "\r\n";

            headers << http_nocache;

            headers << "Last-Modified: ";
            std::time_t t = chrono::system_clock::to_time_t(mot.time);
            headers << put_time(std::gmtime(&t), "%a, %d %b %Y %T GMT");
            headers << "\r\n";

            headers << "\r\n";
            const auto headers_str = headers.str();
            int ret = s.send(headers_str.data(), headers_str.size(), MSG_NOSIGNAL);
            if (ret == (ssize_t)headers_str.size()) {
                ret = s.send(mot.data.data(), mot.data.size(), MSG_NOSIGNAL);
            }

            if (ret == -1) {
                cerr << "Failed to send slide" << endl;
            }

            return true;
        }
    }
    return false;
}

bool WebRadioInterface::send_channel(Socket& s)
{
    const auto freq = input.getFrequency();

    try {
        const auto chan = channels.getChannelForFrequency(freq);

        string response = http_ok;
        response += http_contenttype_text;
        response += http_nocache;
        response += "\r\n";
        response += chan;
        ssize_t ret = s.send(response.data(), response.size(), MSG_NOSIGNAL);
        if (ret == -1) {
            cerr << "Failed to send frequency" << endl;
            return false;
        }
    }
    catch (const out_of_range& e) {
        string response = http_500;
        response += http_contenttype_text;
        response += http_nocache;
        response += "\r\n";
        response += "Error: ";
        response += e.what();
        ssize_t ret = s.send(response.data(), response.size(), MSG_NOSIGNAL);
        if (ret == -1) {
            cerr << "Failed to send frequency 500" << endl;
            return false;
        }
    }
    return true;
}

bool WebRadioInterface::handle_fft_window_placement_post(Socket& s, const std::string& fft_window_placement)
{
    cerr << "POST fft window: " << fft_window_placement << endl;

    if (fft_window_placement == "EarliestPeakWithBinning") {
        rro.fftPlacementMethod = FFTPlacementMethod::EarliestPeakWithBinning;
    }
    else if (fft_window_placement == "StrongestPeak") {
        rro.fftPlacementMethod = FFTPlacementMethod::StrongestPeak;
    }
    else if (fft_window_placement == "ThresholdBeforePeak") {
        rro.fftPlacementMethod = FFTPlacementMethod::ThresholdBeforePeak;
    }
    else {
        string response = http_400;
        response += http_contenttype_text;
        response += http_nocache;
        response += "\r\n";
        response += "Invalid FFT Window Placement requested.";
        ssize_t ret = s.send(response.data(), response.size(), MSG_NOSIGNAL);
        if (ret == -1) {
            cerr << "Failed to send frequency" << endl;
            return false;
        }
        return true;
    }

    {
        lock_guard<mutex> lock(rx_mut);
        ASSERT_RX;
        rx->setReceiverOptions(rro);
    }

    string response = http_ok;
    response += http_contenttype_text;
    response += http_nocache;
    response += "\r\n";
    response += "Switched FFT Window Placement.";
    ssize_t ret = s.send(response.data(), response.size(), MSG_NOSIGNAL);
    if (ret == -1) {
        cerr << "Failed to send frequency" << endl;
        return false;
    }
    return true;
}

bool WebRadioInterface::handle_coarse_corrector_post(Socket& s, const std::string& coarseCorrector)
{
    cerr << "POST coarse : " << coarseCorrector << endl;

    if (coarseCorrector == "0") {
        rro.disableCoarseCorrector = true;
    }
    else if (coarseCorrector == "1") {
        rro.disableCoarseCorrector = false;
    }
    else {
        string response = http_400;
        response += http_contenttype_text;
        response += http_nocache;
        response += "\r\n";
        response += "Invalid coarse corrector selected";
        ssize_t ret = s.send(response.data(), response.size(), MSG_NOSIGNAL);
        if (ret == -1) {
            cerr << "Failed to set response" << endl;
            return false;
        }
        return true;
    }

    {
        lock_guard<mutex> lock(rx_mut);
        ASSERT_RX;
        rx->setReceiverOptions(rro);
    }

    string response = http_ok;
    response += http_contenttype_text;
    response += http_nocache;
    response += "\r\n";
    response += "Switched Coarse corrector.";
    ssize_t ret = s.send(response.data(), response.size(), MSG_NOSIGNAL);
    if (ret == -1) {
        cerr << "Failed to send coarse switch confirmation" << endl;
        return false;
    }
    return true;
}

bool WebRadioInterface::handle_channel_post(Socket& s, const std::string& channel)
{
    cerr << "POST channel: " << channel << endl;

    retune(channel);

    string response = http_ok;
    response += http_contenttype_text;
    response += http_nocache;
    response += "\r\n";
    response += "Retuning...";
    ssize_t ret = s.send(response.data(), response.size(), MSG_NOSIGNAL);
    if (ret == -1) {
        cerr << "Failed to send frequency" << endl;
        return false;
    }
    return true;
}

void WebRadioInterface::handle_phs()
{
    while (running) {
        this_thread::sleep_for(chrono::seconds(2));

        unique_lock<mutex> lock(rx_mut);
        ASSERT_RX;

        auto serviceList = rx->getServiceList();
        for (auto& service : serviceList) {
            auto servicecomponent = rx->getComponents(service);

            if (phs.count(service.serviceId) == 0) {
                WebProgrammeHandler ph(service.serviceId);
                phs.emplace(std::make_pair(service.serviceId, move(ph)));
            }
        }

        lock.unlock();
        check_decoders_required();
    }

    cerr << "TEARDOWN Cancel all PHs and remove services" << endl;
    {
        lock_guard<mutex> lock(rx_mut);
        for (auto& ph : phs) {
            ph.second.cancelAll();

            const auto service = rx->getService(ph.first);
            if (service.serviceId != 0) {
                (void)rx->removeServiceToDecode(service);
            }
        }
    }

    cerr << "TEARDOWN Stop rx" << endl;
    {
        unique_lock<mutex> lock(rx_mut);
        rx->stop();
    }
}

#if HAVE_SIGACTION
static volatile sig_atomic_t sig_caught = 0;
static void handler(int /*signum*/)
{
    sig_caught = 1;
}
#else
const int sig_caught = 0;
#endif

void WebRadioInterface::serve()
{
    deque<future<bool> > running_connections;

#if HAVE_SIGACTION
    struct sigaction sa = {};
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        cerr << "Failed to set up signal handler" << endl;
    }
#endif

    while (sig_caught == 0) {
        auto client = serverSocket.accept();

        running_connections.push_back(async(launch::async,
                    &WebRadioInterface::dispatch_client, this, move(client)));

        deque<future<bool> > still_running_connections;
        for (auto& fut : running_connections) {
            if (fut.valid()) {
                switch (fut.wait_for(chrono::milliseconds(1))) {
                    case future_status::deferred:
                    case future_status::timeout:
                        still_running_connections.push_back(move(fut));
                        break;
                    case future_status::ready:
                        fut.get();
                        break;
                }
            }
        }
        running_connections = move(still_running_connections);
    }

    cerr << "SERVE No more connections running" << endl;

    running = false;
    if (programme_handler_thread.joinable()) {
        programme_handler_thread.join();
    }

    cerr << "SERVE Wait for all futures to clear" << endl;
    while (running_connections.size() > 0) {
        deque<future<bool> > still_running_connections;
        for (auto& fut : running_connections) {
            if (fut.valid()) {
                switch (fut.wait_for(chrono::milliseconds(1))) {
                    case future_status::deferred:
                    case future_status::timeout:
                        still_running_connections.push_back(move(fut));
                        break;
                    case future_status::ready:
                        fut.get();
                        break;
                }
            }
        }
        running_connections = move(still_running_connections);
    }

    cerr << "SERVE clear remaining data structures" << endl;
    phs.clear();
    programmes_being_decoded.clear();
}

void WebRadioInterface::onSNR(float snr)
{
    lock_guard<mutex> lock(data_mut);
    last_snr = snr;
}

void WebRadioInterface::onFrequencyCorrectorChange(int fine, int coarse)
{
    lock_guard<mutex> lock(data_mut);
    last_fine_correction = fine;
    last_coarse_correction = coarse;
}

void WebRadioInterface::onSyncChange(char isSync)
{
    synced = isSync;
}

void WebRadioInterface::onSignalPresence(bool /*isSignal*/) { }
void WebRadioInterface::onServiceDetected(uint32_t /*sId*/) { }
void WebRadioInterface::onNewEnsemble(uint16_t /*eId*/) { }
void WebRadioInterface::onSetEnsembleLabel(DabLabel& /*label*/) { }

void WebRadioInterface::onDateTimeUpdate(const dab_date_time_t& dateTime)
{
    lock_guard<mutex> lock(data_mut);
    last_dateTime = dateTime;
}

void WebRadioInterface::onFIBDecodeSuccess(bool crcCheckOk, const uint8_t* fib)
{
    if (not crcCheckOk) {
        lock_guard<mutex> lock(fib_mut);
        num_fic_crc_errors++;
        return;
    }

    // Convert the fib bitvector to bytes
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

    {
        lock_guard<mutex> lock(fib_mut);
        fib_blocks.push_back(move(buf));

        if (fib_blocks.size() > 3*250) { // six seconds
            fib_blocks.pop_front();
        }
    }

    new_fib_block_available.notify_one();
}

void WebRadioInterface::onNewImpulseResponse(std::vector<float>&& data) { }
void WebRadioInterface::onNewNullSymbol(std::vector<DSPCOMPLEX>&& data) { }
void WebRadioInterface::onConstellationPoints(std::vector<DSPCOMPLEX>&& data) { }
void WebRadioInterface::onMessage(message_level_t level, const std::string& text, const std::string& text2) { }
void WebRadioInterface::onTIIMeasurement(tii_measurement_t&& m) { }

void WebRadioInterface::onInputFailure()
{
    std::exit(1);
}

list<tii_measurement_t> WebRadioInterface::getTiiStats()
{
    list<tii_measurement_t> l;

    for (const auto& cp_list : tiis) {
        const auto comb = cp_list.first.first;
        const auto pattern = cp_list.first.second;

        if (cp_list.second.size() < 5) {
            continue;
        }

        tii_measurement_t avg;
        avg.comb = comb;
        avg.pattern = pattern;
        vector<int> delays;
        double error = 0.0;
        size_t len = 0;
        for (const auto& meas : cp_list.second) {
            delays.push_back(meas.delay_samples);
            error += meas.error;
            len++;
        }

        if (len > 0) {
            avg.error = error / len;

            // Calculate the median
            std::nth_element(delays.begin(), delays.begin() + len/2, delays.end());
            avg.delay_samples = delays[len/2];
        }
        else {
            // To quiet static analysis check
            avg.error = 0.0;
            avg.delay_samples = 0;
        }
        l.push_back(move(avg));
    }

    using namespace std::chrono;
    const auto now = steady_clock::now();
    // Remove a single entry every second to make the flukes
    // disappear
    if (time_last_tiis_clean + seconds(1) > now) {
        for (auto& cp_list : tiis) {
            cp_list.second.pop_front();
        }

        time_last_tiis_clean = now;
    }

    return l;
}
