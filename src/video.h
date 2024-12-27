#ifndef VIDEO_H
#define VIDEO_H

#include <iostream>
#include <vector>
// write()
#include <unistd.h>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/imgutils.h>
#include <libavutil/avutil.h>
#include <libswscale/swscale.h>
}
using namespace std;
#include <openssl/ssl.h>

void send_video_backend(const string &video_path, SSL* ssl, const string &receiver) {
	// Initialize FFmpeg libraries
	// av_register_all(); // Deprecated and removed in newer versions of FFmpeg
	avformat_network_init();

	AVFormatContext *format_ctx = nullptr;
	if (avformat_open_input(&format_ctx, video_path.c_str(), nullptr, nullptr) != 0) {
		cerr << "Error: Couldn't open video file." << endl;
		return;
	}

	if (avformat_find_stream_info(format_ctx, nullptr) < 0) {
		cerr << "Error: Couldn't find stream information." << endl;
		avformat_close_input(&format_ctx);
		return;
	}

	// Find the first video stream
	int video_stream_index = -1;
	AVCodecParameters *codec_params = nullptr;
	for (int i = 0; i < format_ctx->nb_streams; i++) {
		if (format_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
			video_stream_index = i;
			codec_params = format_ctx->streams[i]->codecpar;
			break;
		}
	}

	if (video_stream_index == -1) {
		cerr << "Error: Couldn't find video stream." << endl;
		avformat_close_input(&format_ctx);
		return;
	}

	// Find the decoder for the video stream
	const AVCodec *codec = avcodec_find_decoder(codec_params->codec_id);
	if (!codec) {
		cerr << "Error: Couldn't find codec." << endl;
		avformat_close_input(&format_ctx);
		return;
	}

	AVCodecContext *codec_ctx = avcodec_alloc_context3(codec);
	if (!codec_ctx) {
		cerr << "Error: Couldn't allocate codec context." << endl;
		avformat_close_input(&format_ctx);
		return;
	}

	if (avcodec_parameters_to_context(codec_ctx, codec_params) < 0) {
		cerr << "Error: Couldn't copy codec parameters to context." << endl;
		avcodec_free_context(&codec_ctx);
		avformat_close_input(&format_ctx);
		return;
	}

	if (avcodec_open2(codec_ctx, codec, nullptr) < 0) {
		cerr << "Error: Couldn't open codec." << endl;
		avcodec_free_context(&codec_ctx);
		avformat_close_input(&format_ctx);
		return;
	}

	// Initialize the packet and frame
	AVPacket packet;
	AVFrame *frame = av_frame_alloc();
	if (!frame) {
		cerr << "Error: Couldn't allocate frame." << endl;
		avcodec_free_context(&codec_ctx);
		avformat_close_input(&format_ctx);
		return;
	}

	// Set up the H.264 encoder
	const AVCodec *encoder = avcodec_find_encoder(AV_CODEC_ID_H264);
	if (!encoder) {
		cerr << "Error: Couldn't find H.264 encoder." << endl;
		av_frame_free(&frame);
		avcodec_free_context(&codec_ctx);
		avformat_close_input(&format_ctx);
		return;
	}

	AVCodecContext *encoder_ctx = avcodec_alloc_context3(encoder);
	if (!encoder_ctx) {
		cerr << "Error: Couldn't allocate encoder context." << endl;
		av_frame_free(&frame);
		avcodec_free_context(&codec_ctx);
		avformat_close_input(&format_ctx);
		return;
	}

	encoder_ctx->bit_rate = 400000;
	encoder_ctx->width = codec_ctx->width;
	encoder_ctx->height = codec_ctx->height;
	encoder_ctx->time_base = {1, 30}; // 30 fps
	encoder_ctx->pix_fmt = AV_PIX_FMT_YUV420P;

	if (avcodec_open2(encoder_ctx, encoder, nullptr) < 0) {
		cerr << "Error: Couldn't open encoder." << endl;
		avcodec_free_context(&encoder_ctx);
		av_frame_free(&frame);
		avcodec_free_context(&codec_ctx);
		avformat_close_input(&format_ctx);
		return;
	}

	// Read frames from the video and send them encoded
	while (av_read_frame(format_ctx, &packet) >= 0) {
		if (packet.stream_index == video_stream_index) {
			if (avcodec_send_packet(codec_ctx, &packet) < 0) {
				cerr << "Error: Failed to send packet for decoding." << endl;
				break;
			}

			while (avcodec_receive_frame(codec_ctx, frame) >= 0) {
				// Encode the frame
				if (avcodec_send_frame(encoder_ctx, frame) < 0) {
					cerr << "Error: Failed to send frame for encoding." << endl;
					break;
				}

				AVPacket encoded_packet;
				av_init_packet(&encoded_packet);
				if (avcodec_receive_packet(encoder_ctx, &encoded_packet) >= 0) {
					// Send the encoded packet
					string buf = "! " + receiver + " -1 " + to_string(encoded_packet.size) + " -1 0 ";
					buf.append(reinterpret_cast<char*>(encoded_packet.data), encoded_packet.size);
					int len = buf.size();
					//cerr << "sending " << len << " bytes\n";
					uint32_t net_len = htonl(len);
					int n = SSL_write_all(ssl, &net_len, sizeof(net_len));
					if (n < 0 || n != sizeof(net_len)) {
						cerr << "Error: Failed to write length to SSL socket." << endl;
						av_packet_unref(&encoded_packet);
						break;
					}
					n = SSL_write_all(ssl, buf.data(), buf.size());
					if (n < 0 || n != buf.size()) {
						cerr << "Error: Failed to write to SSL socket." << endl;
						av_packet_unref(&encoded_packet);
						cerr << "Send " << n << " bytes." << endl;
						break;
					}
					// sleep 0.001s
					usleep(30*1000);
					av_packet_unref(&encoded_packet);
				}
			}
		}
		av_packet_unref(&packet);
	}

	//write last message
	string buf = "! " + receiver + " -1 -1 -1 1 ";
	int len = buf.size();
	uint32_t net_len = htonl(len);
	int n = SSL_write(ssl, &net_len, sizeof(net_len));
	if (n < 0 || n != sizeof(net_len)) {
		cerr << "Error: Failed to write length to SSL socket." << endl;
	}
	n = SSL_write(ssl, buf.c_str(), buf.size());
	if(n < 0 || n != buf.size()){
		cerr << "Error: Failed to write to SSL socket." << endl;
	}

	// Cleanup
	av_frame_free(&frame);
	avcodec_free_context(&encoder_ctx);
	avcodec_free_context(&codec_ctx);
	avformat_close_input(&format_ctx);
}

#endif // VIDEO_H
