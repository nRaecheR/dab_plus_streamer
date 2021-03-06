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
#include "webprogrammehandler.h"
#include <iostream>
#include <algorithm>

using namespace std;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

ProgrammeSender::ProgrammeSender(Socket&& s) :
    s(move(s))
{
}

ProgrammeSender::ProgrammeSender(ProgrammeSender&& other) :
    s(move(other.s))
{
}

ProgrammeSender& ProgrammeSender::operator=(ProgrammeSender&& other)
{
    s = move(other.s);
    other.running = false;
    return *this;
}

bool ProgrammeSender::send_mp3(const std::vector<uint8_t>& mp3Data)
{
    if (not s.valid()) {
        return false;
    }

    const int flags = MSG_NOSIGNAL;

    ssize_t ret = s.send(mp3Data.data(), mp3Data.size(), flags);
    if (ret == -1) {
        s.close();
        std::unique_lock<std::mutex> lock(mutex);
        running = false;
        lock.unlock();
        cv.notify_all();
        return false;
    }

    return true;
}

void ProgrammeSender::wait_for_termination() const
{
    std::unique_lock<std::mutex> lock(mutex);
    while (running) {
        cv.wait_for(lock, chrono::seconds(2));
    }
}

void ProgrammeSender::cancel()
{
    s.close();
    running = false;
}

WebProgrammeHandler::WebProgrammeHandler(uint32_t serviceId) :
    serviceId(serviceId)
{
    const auto now = chrono::system_clock::now();
    time_label = now;
    time_label_change = now;
    time_mot = now;
    time_mot_change = now;
}

WebProgrammeHandler::WebProgrammeHandler(WebProgrammeHandler&& other) :
    serviceId(other.serviceId),
    senders(move(other.senders))
{
    other.senders.clear();
    other.serviceId = 0;

    const auto now = chrono::system_clock::now();
    time_label = now;
    time_label_change = now;
    time_mot = now;
    time_mot_change = now;
}

void WebProgrammeHandler::registerSender(ProgrammeSender *sender)
{
    std::unique_lock<std::mutex> lock(senders_mutex);
    senders.push_back(sender);
}

void WebProgrammeHandler::removeSender(ProgrammeSender *sender)
{
    std::unique_lock<std::mutex> lock(senders_mutex);
    senders.remove(sender);
}

bool WebProgrammeHandler::needsToBeDecoded() const
{
    std::unique_lock<std::mutex> lock(senders_mutex);
    return not senders.empty();
}

void WebProgrammeHandler::cancelAll()
{
    std::unique_lock<std::mutex> lock(senders_mutex);
    for (auto& s : senders) {
        s->cancel();
    }
}

WebProgrammeHandler::dls_t WebProgrammeHandler::getDLS() const
{
    dls_t dls;

    std::unique_lock<std::mutex> lock(stats_mutex);
    if (last_label_valid) {
        dls.label = last_label;
        dls.time = time_label;
        dls.last_changed = time_label_change;
    }

    return dls;
}

WebProgrammeHandler::mot_t WebProgrammeHandler::getMOT() const
{
    mot_t mot;

    std::unique_lock<std::mutex> lock(stats_mutex);
    if (last_mot_valid) {
        mot.data = last_mot;
        mot.time = time_mot;
        mot.last_changed = time_mot_change;
        mot.subtype = last_subtype;
    }
    return mot;
}

WebProgrammeHandler::xpad_error_t WebProgrammeHandler::getXPADErrors() const
{
    std::unique_lock<std::mutex> lock(stats_mutex);
    xpad_error_t r(xpad_error);
    return r;
}

WebProgrammeHandler::audiolevels_t WebProgrammeHandler::getAudioLevels() const
{
    std::unique_lock<std::mutex> lock(stats_mutex);
    audiolevels_t r(audiolevels);
    return r;
}

WebProgrammeHandler::errorcounters_t WebProgrammeHandler::getErrorCounters() const
{
    std::unique_lock<std::mutex> lock(stats_mutex);
    errorcounters_t r(errorcounters);
    return r;
}

void WebProgrammeHandler::onFrameErrors(int frameErrors)
{
    std::unique_lock<std::mutex> lock(stats_mutex);
    errorcounters.num_frameErrors += frameErrors;
    errorcounters.time = chrono::system_clock::now();
}

void WebProgrammeHandler::onNewAudio(std::vector<int16_t>&& audioData,
                int sampleRate, const string& m)
{
    rate = sampleRate;
    mode = m;

    if (audioData.empty()) {
        return;
    }

    // The audio decoders always upconvert to stereo
    const int channels = 2;

    int last_audioLevel_L = 0;
    int last_audioLevel_R = 0;
    {
        int16_t max_L = 0;
        int16_t max_R = 0;
        for (size_t i = 0; i < audioData.size()-1; i+=2) {
            max_L = std::max(max_L, audioData[i]);
            max_R = std::max(max_R, audioData[i+1]);
        }
        last_audioLevel_L = max_L;
        last_audioLevel_R = max_R;
    }

    {
        std::unique_lock<std::mutex> lock(stats_mutex);
        audiolevels.time = chrono::system_clock::now();
        audiolevels.last_audioLevel_L = last_audioLevel_L;
        audiolevels.last_audioLevel_R = last_audioLevel_R;
    }

    if (not lame_initialised) {
        lame_set_in_samplerate(lame.lame, rate);
        lame_set_num_channels(lame.lame, channels);
        lame_set_VBR(lame.lame, vbr_default);
        lame_set_VBR_q(lame.lame, 0);
		lame_set_VBR_min_bitrate_kbps( lame.lame, 96 );
		lame_set_VBR_max_bitrate_kbps( lame.lame, 320 );
        lame_init_params(lame.lame);
        lame_initialised = true;
    }

    vector<uint8_t> mp3buf(16384);

    int written = lame_encode_buffer_interleaved(lame.lame,
            audioData.data(), audioData.size()/channels,
            mp3buf.data(), mp3buf.size());

    if (written < 0) {
        cerr << "Failed to encode mp3: " << written << endl;
    }
    else if (written > (ssize_t)mp3buf.size()) {
        cerr << "mp3 encoder wrote more than buffer size!" << endl;
    }
    else if (written > 0) {
        mp3buf.resize(written);

        std::unique_lock<std::mutex> lock(senders_mutex);

        for (auto& s : senders) {
            bool success = s->send_mp3(mp3buf);
            if (not success) {
                cerr << "Failed to send audio for " << serviceId << endl;
            }
        }
    }
}

void WebProgrammeHandler::onRsErrors(bool uncorrectedErrors, int numCorrectedErrors)
{
    (void)numCorrectedErrors; // TODO calculate BER before Reed-Solomon
    std::unique_lock<std::mutex> lock(stats_mutex);
    errorcounters.num_rsErrors += (uncorrectedErrors ? 1 : 0);
    errorcounters.time = chrono::system_clock::now();
}

void WebProgrammeHandler::onAacErrors(int aacErrors)
{
    std::unique_lock<std::mutex> lock(stats_mutex);
    errorcounters.num_aacErrors += aacErrors;
    errorcounters.time = chrono::system_clock::now();
}

void WebProgrammeHandler::onNewDynamicLabel(const string& label)
{
    std::unique_lock<std::mutex> lock(stats_mutex);
    last_label_valid = true;
    const auto now = chrono::system_clock::now();
    time_label = now;
    if (last_label != label) {
        time_label_change = now;
    }
    last_label = label;
}

void WebProgrammeHandler::onMOT(const mot_file_t& mot_file)
{
    std::unique_lock<std::mutex> lock(stats_mutex);
    last_mot_valid = true;
    const auto now = chrono::system_clock::now();
    time_mot = now;
    if (last_mot != mot_file.data) {
        time_mot_change = now;
    }
    last_mot = mot_file.data;
    if (mot_file.content_sub_type == 0x01) {
        last_subtype = MOTType::JPEG;
    }
    else if (mot_file.content_sub_type == 0x03) {
        last_subtype = MOTType::PNG;
    }
    else {
        last_subtype = MOTType::Unknown;
    }
}

void WebProgrammeHandler::onPADLengthError(size_t announced_xpad_len, size_t xpad_len)
{
    std::unique_lock<std::mutex> lock(stats_mutex);
    xpad_error.has_error = true;
    xpad_error.time = chrono::system_clock::now();
    xpad_error.announced_xpad_len = announced_xpad_len;
    xpad_error.xpad_len = xpad_len;
}

