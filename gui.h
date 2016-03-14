#
/*
 *    Copyright (C)  2010, 2011, 2012
 *    Jan van Katwijk (J.vanKatwijk@gmail.com)
 *    Lazy Chair Programming
 *
 *    This file is part of the SDR-J.
 *    Many of the ideas as implemented in SDR-J are derived from
 *    other work, made available through the GNU general Public License. 
 *    All copyrights of the original authors are recognized.
 *
 *    SDR-J is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    SDR-J is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with SDR-J; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _GUI
#define _GUI

#include	"dab-constants.h"
#include	<QDialog>
#include	"ui_sdrgui.h"
#include	<QTimer>
#include	<sndfile.h>
#include	<QStringList>
#include	<QStringListModel>
#include	<QUdpSocket>
#include	"ofdm-processor.h"
#include	"ringbuffer.h"

class	QSettings;
class	Scope;
class	virtualInput;
class	audioSink;

class	mscHandler;
class	ficHandler;

class	common_fft;

#ifdef	TCP_STREAMER
class	tcpStreamer;
#elif	RTP_STREAMER
class	rtpStreamer;
#endif
/*
 *	GThe main gui object. It inherits from
 *	QDialog and the generated form
 */
class RadioInterface: public QDialog,
		      private Ui_dabframe {
Q_OBJECT
public:
		RadioInterface		(QSettings	*,
	                                 QWidget *parent = NULL);
		~RadioInterface		();

private:
#ifdef	TCP_STREAMER
	tcpStreamer	*my_tcpStreamer;
	RingBuffer<float> *streamBuffer;
#elif	RTP_STREAMER
	rtpStreamer	*my_rtpStreamer;
	RingBuffer<float> *streamBuffer;
#endif
	int16_t		threshold;
	int16_t		outputDevice;
	void		dumpControlState	(QSettings *);
	bool		sourceDumping;
	SNDFILE		*dumpfilePointer;
	bool		audioDumping;
	SNDFILE		*audiofilePointer;
	bool		Concurrent;
	DabParams	dabModeParameters;
	void		setModeParameters	(int16_t);
	int32_t		vfoFrequency;
	int32_t		vfoOffset;
	QSettings	*dabSettings;
	QStringListModel	ensemble;
	QStringList	Services;

	char		isSynced;
	int32_t		outRate;

	void		setupChannels	(QComboBox *, uint8_t);
	uint8_t		dabBand;
	uint8_t		theProcessor;
	int32_t		ringbufferSize;
	bool		running;

	QString		ensembleLabel;
	virtualInput	*myRig;
	int16_t		*outTable;
	int16_t		numberofDevices;

	void		setTuner		(int32_t);

	QTimer		*displayTimer;
	int32_t		numberofSeconds;

	bool		setupSoundOut		(QComboBox *, audioSink *,
	                                         int16_t *);
	void		resetSelector		(void);
	int32_t		sampleCount;
	ofdmProcessor	*my_ofdmProcessor;
	ficHandler	*my_ficHandler;
	mscHandler	*my_mscHandler;
	audioSink	*our_audioSink;
	int32_t		TunedFrequency;
	bool		autoCorrector;
	FILE		*mp2File;
	FILE		*mp4File;
	int16_t		currentGain;
const	char		*get_programm_type_string (uint8_t);
const	char		*get_programm_language_string (uint8_t);
	QLabel		*pictureLabel;
	QUdpSocket	DSCTy_59_socket;
	int16_t		ficBlocks;
	int16_t		ficSuccess;
private slots:
	void	setStart		(void);
	void	updateTimeDisplay	(void);
	void	setStreamOutSelector	(int);

	void	selectMode		(const QString &);
	void	autoCorrector_on	(void);

	void	abortSystem		(int);
	void	TerminateProcess	(void);
	void	set_bandSelect		(QString);
	void	set_channelSelect	(QString);
	void	setDevice		(QString);
	void	selectService		(QModelIndex);
	void	set_dumping		(void);
	void	set_audioDump		(void);
public slots:
	void	set_fineCorrectorDisplay	(int);
	void	set_coarseCorrectorDisplay	(int);
	void	clearEnsemble		(void);
	void	addtoEnsemble		(const QString &);
	void	nameofEnsemble		(int, const QString &);
	void	show_successRate	(int);
	void	show_ficCRC		(bool);
	void	show_snr		(int);
	void	setSynced		(char);
	void	showLabel		(QString);
	void	showMOT			(QByteArray, int);
	void	send_datagram		(char *, int);
	void	changeinConfiguration	(void);
#ifdef	RTP_STREAMER
	void	samplesforStreamer	(int);
#elif	TCP_STREAMER
	void	samplesforStreamer	(int);
#endif
};

#endif

