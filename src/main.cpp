#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <crypto++/cryptlib.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>

#include <iostream>
#include <memory>
#include <utility>
#include <mutex>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/optional/optional_io.hpp>

using boost::asio::ip::tcp;
namespace po = boost::program_options;

//! The class that implements a single TCP session
class session
	: public std::enable_shared_from_this<session>
{
public:
	//! Constructor takes newly created socket and allocates buffer of max_buffer_length for incoming TCP chunks
	session(tcp::socket socket, size_t max_buffer_length)
		: socket_(std::move(socket))
		, max_buffer_length_(max_buffer_length)
	{
		data_.resize(max_buffer_length);
		// Avoid allocations, SHA256 has hex representation of 64 chars,
		// e.g. two bytes per character plus '\n' plus '\0'
		// We reserve for at least 256 hashes 
		output_.reserve(256 * (2 * CryptoPP::SHA256::DIGESTSIZE + 1) + 1);
		encoder_.Attach(new CryptoPP::StringSink(output_));
	}

	void start()
	{
		do_read();
	}

private:
	void do_read()
	{
		// std::cerr << "do_read" << std::endl;
		auto self(shared_from_this());
		socket_.async_read_some(boost::asio::buffer(&data_[0], data_.size()),
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				std::lock_guard<std::mutex> lock(m_);
				assert(data_.size() == max_buffer_length_);
				byte* buffer_reminder = &data_[0];
				byte* buffer_end = buffer_reminder + length; // to form an STL style range
				// std::cerr << "Arrived " << length << std::endl;
				while (buffer_reminder < buffer_end)
				{
					assert(buffer_reminder <= buffer_end);
					byte* newline_ptr = reinterpret_cast<byte*>(
						::memchr(buffer_reminder, '\n', buffer_end - buffer_reminder));

					bool we_need_to_emit_hash = false;
					if (nullptr == newline_ptr)
					{
						// New line character is not found
						hash_.Update(buffer_reminder, buffer_end - buffer_reminder);
						buffer_reminder = buffer_end;
					}
					else
					{
						assert(buffer_reminder <= newline_ptr);
						hash_.Update(buffer_reminder, newline_ptr - buffer_reminder + 1);
						we_need_to_emit_hash = true; // new line found, we need to emit hash
						buffer_reminder = newline_ptr + 1;
					}

					if (ec) // emit hash on end of stream
					{
						// std::cerr << "Error code " << ec.message() << std::endl;
						we_need_to_emit_hash = true;
					}

					if (we_need_to_emit_hash)
					{
						hash_.Final(digest_);

						encoder_.Put(digest_, sizeof(digest_));
						encoder_.MessageEnd();

						output_.append(1, '\n');
						// std::cerr << "SHA256: " << output_;
					} 
				}

				do_write(ec);
			});
	}

	void do_write(bool final)
	{
		// std::cerr << "do_write" << std::endl;
		auto self(shared_from_this());
		boost::asio::async_write(socket_, boost::asio::buffer(output_.c_str(), output_.size()),
			[this, self, final](boost::system::error_code ec, std::size_t /*length*/)
			{
				std::lock_guard<std::mutex> lock(m_);
				// std::cerr << "Written " << output_ << std::endl;
				output_.clear();
				if (!ec && !final)
				{
					do_read();
				}
			});
	}

	std::mutex m_;
	tcp::socket socket_;
	size_t max_buffer_length_ = 0;

	std::vector<byte> data_;
	CryptoPP::SHA256 hash_;
	byte digest_[CryptoPP::SHA256::DIGESTSIZE];
	CryptoPP::HexEncoder encoder_;
	std::string output_;
};

//! Accepts new TCP connections on specified port
class server
{
public:

	//! It is likely that setting up a larger buffer will increase performance, however
	//! we do not want to increase memory requirements per one TCP connection
	static const size_t default_max_buffer_length = 2 * 1024;

	//! Construct server
	server(boost::asio::io_service& io_service /*< use this io_service */, 
		unsigned short port /*< listen to this port */, 
		size_t max_buffer_length = default_max_buffer_length /*< established connections will be using the buffer of this size for incoming messages */)
		: acceptor_(io_service, tcp::endpoint(tcp::v4(), port))
		, socket_(io_service)
		, max_buffer_length_(max_buffer_length)
	{
		do_accept();
	}

private:
	void do_accept()
	{
		acceptor_.async_accept(socket_,
			[this](boost::system::error_code ec)
			{
				if (!ec)
				{
					std::make_shared<session>(std::move(socket_), max_buffer_length_)->start();
				}

				do_accept();
			});
	}

	tcp::acceptor acceptor_;
	tcp::socket socket_;
	size_t max_buffer_length_{default_max_buffer_length};
};

//! Class that contains all required functionality (in main()).
//! It can also be instantiated several times for unit tests 
struct hash_service
{
	//! Constructor which takes port number and size of receiving buffer (in bytes)
	hash_service(unsigned short port /*< listen to */, size_t buffer_length /*< receive TCP stream data by the chunks of this size */)
		: s_{ io_service_, port, buffer_length }
	{
	}

    //! Creates thread-pool and starts listening to required port. 
    //! Size of the thread-pool is determined by boost::thread::hardware_concurrency()
	void run() {
		// std::cerr << "Hardware concurrency: " << boost::thread::hardware_concurrency() << std::endl;
		for (unsigned i = 0; i < boost::thread::hardware_concurrency(); ++i)
			tg_.create_thread(boost::bind(&boost::asio::io_service::run, &io_service_));
	}

	//! Stop the service. After stopping we need to wait until all the threads in the thread-pool are exited. 
	//! This can be done by calling join().
	//! Overall sequence must be: 1) interrupt() 2) join()
	void interrupt()
	{
		// std::cerr << "Asio stop" << std::endl;
		io_service_.stop();
		// std::cerr << "Interrupt all" << std::endl;
		// tg_.interrupt_all();
	}

	//! Block the calling thread until all the treads in thread-pool are exited
	void join()
	{
		tg_.join_all();
	}

private:
	boost::asio::io_service io_service_;
	server s_;
	boost::thread_group tg_;
};



#if defined(HASH_SERVER_TESTS)

#include "gtest/gtest.h"
#include <fstream>

std::string exec(const std::string& cmd) {
	std::array<char, 256> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

void write_to_file(const std::string& file_name, size_t n_copies, const std::string& contents)
{
	std::ofstream out(file_name);
	for (size_t i = 0; i < n_copies; ++i)
		out << contents;
	out.close();
}

void test_with_specified_size(unsigned short port, size_t buffer_size)
{
	hash_service server_instance(port, buffer_size);
	server_instance.run();
	size_t n_copies = 4 * 1024;

	// telnet command ends lines with \r\n combination
	// we need to simulate this behaviour with netcat to match hashes
	write_to_file("input.txt", n_copies,
		"1\r\n"
		"22\r\n"
		"333\r\n"
		"4444\r\n");

	write_to_file("output.txt", n_copies,
		"F1B2F662800122BED0FF255693DF89C4487FBDCF453D3524A42D4EC20C3D9C04\n"
		"12D3A4EFA6646B3ECE4782F70033B9785BF0D167B553C43E22579B031CEA5C4D\n"
		"F407DF8F8E7A374565BBFF2C11FCF2B37FBBC6F070CA9E1317240FC9A90C6675\n"
		"4A325BE077D8A33AD25ED3462CD232AE8367AF77F8070E8E4090670BE7ECBA5A\n");

	std::string bad_command = std::string("/bin/bash -c \"cat input.txt | nc localhost ") + std::to_string(port) + " | diff input.txt - \"";
	// std::cerr << bad_command << std::endl;
	EXPECT_FALSE(exec(bad_command).empty());
	std::string good_command = std::string("/bin/bash -c \"cat input.txt | nc localhost ") + std::to_string(port) + " | diff output.txt - \"";
	// std::cerr << good_command << std::endl;
	EXPECT_TRUE(exec(good_command).empty());

	server_instance.interrupt();
	server_instance.join();
}

TEST(server_test, buffer_size_1) 
{
	test_with_specified_size(59991, 1);
}

TEST(server_test, buffer_size_2)
{
	test_with_specified_size(59992, 2);
}

TEST(server_test, buffer_size_3)
{
	test_with_specified_size(59993, 3);
}

TEST(server_test, buffer_size_2048)
{
	test_with_specified_size(59994, 2048);
}

int main(int argc, char* argv[])
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

#else

int main(int argc, char* argv[])
{
	try
	{
		unsigned short default_port = 59999;

		po::options_description desc("Usage: hash-server [options]\nAll options:\n");
		desc.add_options()
			("port,p", "serve at the specified TCP port number, must be in the range 1024-65535")
			("help,h", "produce help message");

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help")) 
		{
			std::cout << desc << "\n";
			return 1;
		}

		boost::optional<int> port;
		if (0 == vm.count("port"))
		{
			port = default_port;
		}
		else
		{
			try
			{
				port = vm["port"].as<int>();
				if (1024 <= port.get() && port.get() <= 65535)
				{
					throw std::out_of_range("Port must be in the range 1024-65535");
				}
			}
			catch (const std::exception& e)
			{
				std::cout << "Invalid port number: " << vm["port"].as<std::string>() << " " << e.what() << std::endl;
			}
		}

		if (port) 
		{
			std::cout << "Port was set to " << port.get() << ".\nTo get help on program options use: hash-server -h\n";
			hash_service server_instance(port.get(), /* buffer_length = */ 2 * 1024);
			server_instance.run();
			server_instance.join();
		}
	}
	catch (std::exception & e)
	{
		std::cerr << "Exception: " << e.what() << std::endl;
	}

	return 0;
}
#endif

