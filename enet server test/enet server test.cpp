/**********************************************************************************
    First Growtopia Private Server made with ENet.
    Copyright (C) 2018  Growtopia Noobs

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************************************************/


#include "stdafx.h"
#include <iostream>

#include "enet/enet.h"
#include <string>
#include <algorithm> 
#include <cctype>
#include <locale>
#include <cstdio>
#include <windows.h>
#include <conio.h>
#include <vector>
#include <sstream>
#include <chrono>
#include <fstream>
#include <regex>
#include "json.hpp"
#include "bcrypt.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.cpp"

#pragma warning(disable : 4996)

using std::string;
using std::cout;
using std::endl;
using std::vector;

using json = nlohmann::json;
string newslist = "set_default_color|`o\n\nadd_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|`4WARNING:`` `5Worlds (and accounts)`` might be deleted at any time if database issues appear (once per day or week).|left|4|\nadd_label_with_icon|small|`4WARNING:`` `5Accounts`` are in beta, bugs may appear and they will be probably deleted often, because of new account updates, which will cause database incompatibility.|left|4|\nadd_spacer|small|\n\nadd_url_button||``Watch: `1Watch a video about GT Private Server``|NOFLAGS|https://www.youtube.com/watch?v=_3avlDDYBBY|Open link?|0|0|\nadd_url_button||``Channel: `1Watch Growtopia Noobs' channel``|NOFLAGS|https://www.youtube.com/channel/UCLXtuoBlrXFDRtFU8vPy35g|Open link?|0|0|\nadd_url_button||``Items: `1Item database by Nenkai``|NOFLAGS|https://raw.githubusercontent.com/Nenkai/GrowtopiaItemDatabase/master/GrowtopiaItemDatabase/CoreData.txt|Open link?|0|0|\nadd_url_button||``Discord: `1GT Private Server Discord``|NOFLAGS|https://discord.gg/8WUTs4v|Open the link?|0|0|\nadd_quick_exit|\n\nend_dialog|gazette|Close||";

#define REGISTRATION
#include <signal.h>
ENetHost * server;
int cId = 1;
BYTE* itemsDat = 0;
int itemsDatSize = 0;


//configs
int configPort = 17091;
string configCDN = "0098/CDNContent59/cache/";


/***bcrypt***/

bool verifyPassword(string password, string hash) {
	int ret = bcrypt_checkpw(password.c_str(), hash.c_str());
	assert(ret != -1);
	
	return !ret;
}

bool has_only_digits(const string str)
{
    return str.find_first_not_of("0123456789") == std::string::npos;
}

string hashPassword(string password) {
	char salt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	int ret;
	
	ret = bcrypt_gensalt(12, salt);
	assert(ret == 0);
	ret = bcrypt_hashpw(password.c_str(), salt, hash);
	assert(ret == 0);
	return hash;
}

/***bcrypt**/

void sendData(ENetPeer* peer, int num, char* data, int len)
{
	/* Create a reliable packet of size 7 containing "packet\0" */
	ENetPacket * packet = enet_packet_create(0,
		len + 5,
		ENET_PACKET_FLAG_RELIABLE);
	/* Extend the packet so and append the string "foo", so it now */
	/* contains "packetfoo\0"                                      */
	/* Send the packet to the peer over channel id 0. */
	/* One could also broadcast the packet by         */
	/* enet_host_broadcast (host, 0, packet);         */
	memcpy(packet->data, &num, 4);
	if (data != NULL)
	{
		memcpy(packet->data+4, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 4 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);
}

int getPacketId(char* data)
{
	return *data;
}

char* getPacketData(char* data)
{
	return data + 4;
}

string text_encode(char* text)
{
	string escaped = text;
	escaped = std::regex_replace(escaped, std::regex("\n"), "\\n");
	escaped = std::regex_replace(escaped, std::regex("\t"), "\\t");
	escaped = std::regex_replace(escaped, std::regex("\b"), "\\b");
	escaped = std::regex_replace(escaped, std::regex("\\"), "\\\\");
	escaped = std::regex_replace(escaped, std::regex("\r"), "\\r");
	return escaped;
}

int ch2n(char x)
{
	switch (x)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'A':
		return 10;
	case 'B':
		return 11;
	case 'C':
		return 12;
	case 'D':
		return 13;
	case 'E':
		return 14;
	case 'F':
		return 15;
	default:
		break;
	}
}


char* GetTextPointerFromPacket(ENetPacket* packet)
{
	char zero = 0;
	memcpy(packet->data + packet->dataLength - 1, &zero, 1);
	return (char*)(packet->data + 4);
}

BYTE* GetStructPointerFromTankPacket(ENetPacket* packet)
{
	unsigned int packetLenght = packet->dataLength;
	BYTE* result = NULL;
	if (packetLenght >= 0x3C)
	{
		BYTE* packetData = packet->data;
		result = packetData + 4;
		if (*(BYTE*)(packetData + 16) & 8)
		{
			if (packetLenght < *(int*)(packetData + 56) + 60)
			{
				cout << "Packet too small for extended packet to be valid" << endl;
				cout << "Sizeof float is 4.  TankUpdatePacket size: 56" << endl;
				result = 0;
			}
		}
		else
		{
			int zero = 0;
			memcpy(packetData + 56, &zero, 4);
		}
	}
	return result;
}

int GetMessageTypeFromPacket(ENetPacket* packet)
{
	int result;

	if (packet->dataLength > 3u)
	{
		result = *(packet->data);
	}
	else
	{
		cout << "Bad packet length, ignoring message" << endl;
		result = 0;
	}
	return result;
}


vector<string> explode(const string &delimiter, const string &str)
{
	vector<string> arr;

	int strleng = str.length();
	int delleng = delimiter.length();
	if (delleng == 0)
		return arr;//no change

	int i = 0;
	int k = 0;
	while (i<strleng)
	{
		int j = 0;
		while (i + j<strleng && j<delleng && str[i + j] == delimiter[j])
			j++;
		if (j == delleng)//found delimiter
		{
			arr.push_back(str.substr(k, i - k));
			i += delleng;
			k = i;
		}
		else
		{
			i++;
		}
	}
	arr.push_back(str.substr(k, i - k));
	return arr;
}

struct GamePacket
{
private:
	// We want to be sure this isn't accidentally copied.
	GamePacket(GamePacket const&) = delete;
	GamePacket& operator=(GamePacket const&) = delete;

	GamePacket() {
		BYTE* packetData = new BYTE[61];
		string asdf = "0400000001000000FFFFFFFF00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(packetData + (i / 2), &x, 1);
			if (asdf.length() > 61 * 2) throw 0;
		}
		this->data = packetData;
		this->len = 61;
		this->indexes = 0;
	}
	
	friend class GamePacketBuilder;

public:
	BYTE* data;
	int len;
	int indexes;
	/**
	 * Sends the packet to the given peer. Takes ownership of self.
	 */
	void send(ENetPeer* peer) {
		ENetPacket* packet = enet_packet_create(this->data,
			this->len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
	}

	GamePacket(GamePacket&& packet) noexcept {
		this->data = packet.data;
		this->len = packet.len;
		this->indexes = packet.indexes;

		packet.data = NULL;
		packet.len = 0;
		packet.indexes = 0;
	};

	GamePacket& operator=(GamePacket&& packet) noexcept {
		this->data = packet.data;
		this->len = packet.len;
		this->indexes = packet.indexes;

		packet.data = NULL;
		packet.len = 0;
		packet.indexes = 0;
	};

	~GamePacket() {
		delete[] this->data;
	}
};

class GamePacketBuilder {
private:
	GamePacket p;

public:
	GamePacketBuilder& appendFloat(float val) {
		BYTE* n = new BYTE[p.len + 2 + 4];
		memcpy(n, p.data, p.len);
		delete[] p.data;
		p.data = n;
		n[p.len] = p.indexes;
		n[p.len + 1] = 1;
		memcpy(n + p.len + 2, &val, 4);
		p.len = p.len + 2 + 4;
		p.indexes++;
		return *this;
	}

	GamePacketBuilder& appendFloat(float val, float val2)
	{
		BYTE* n = new BYTE[p.len + 2 + 8];
		memcpy(n, p.data, p.len);
		delete[] p.data;
		p.data = n;
		n[p.len] = p.indexes;
		n[p.len + 1] = 3;
		memcpy(n + p.len + 2, &val, 4);
		memcpy(n + p.len + 6, &val2, 4);
		p.len = p.len + 2 + 8;
		p.indexes++;
		return *this;
	}

	GamePacketBuilder& appendFloat(float val, float val2, float val3)
	{
		BYTE* n = new BYTE[p.len + 2 + 12];
		memcpy(n, p.data, p.len);
		delete[] p.data;
		p.data = n;
		n[p.len] = p.indexes;
		n[p.len + 1] = 4;
		memcpy(n + p.len + 2, &val, 4);
		memcpy(n + p.len + 6, &val2, 4);
		memcpy(n + p.len + 10, &val3, 4);
		p.len = p.len + 2 + 12;
		p.indexes++;
		return *this;
	}

	GamePacketBuilder& appendInt(int val)
	{
		BYTE* n = new BYTE[p.len + 2 + 4];
		memcpy(n, p.data, p.len);
		delete[] p.data;
		p.data = n;
		n[p.len] = p.indexes;
		n[p.len + 1] = 9;
		memcpy(n + p.len + 2, &val, 4);
		p.len = p.len + 2 + 4;
		p.indexes++;
		return *this;
	}

	GamePacketBuilder& appendIntx(int val)
	{
		BYTE* n = new BYTE[p.len + 2 + 4];
		memcpy(n, p.data, p.len);
		delete[] p.data;
		p.data = n;
		n[p.len] = p.indexes;
		n[p.len + 1] = 5;
		memcpy(n + p.len + 2, &val, 4);
		p.len = p.len + 2 + 4;
		p.indexes++;
		return *this;
	}

	GamePacketBuilder& appendString(string str)
	{
		BYTE* n = new BYTE[p.len + 2 + str.length() + 4];
		memcpy(n, p.data, p.len);
		delete[] p.data;
		p.data = n;
		n[p.len] = p.indexes;
		n[p.len + 1] = 2;
		int sLen = str.length();
		memcpy(n + p.len + 2, &sLen, 4);
		memcpy(n + p.len + 6, str.c_str(), sLen);
		p.len = p.len + 2 + str.length() + 4;
		p.indexes++;
		return *this;
	}

	GamePacket&& build() {
		BYTE* n = new BYTE[p.len + 1];
		memcpy(n, p.data, p.len);
		delete[] p.data;
		p.data = n;
		char zero = 0;
		memcpy(p.data + p.len, &zero, 1);
		p.len += 1;
		*(int*)(p.data + 56) = p.indexes;
		*(BYTE*)(p.data + 60) = p.indexes;
		return std::move(this->p);
	}
};

struct InventoryItem {
	__int16 itemID;
	__int8 itemCount;
};

struct PlayerInventory {
	vector<InventoryItem> items;
	int inventorySize = 100;
};

#define cloth0 cloth_hair
#define cloth1 cloth_shirt
#define cloth2 cloth_pants
#define cloth3 cloth_feet
#define cloth4 cloth_face
#define cloth5 cloth_hand
#define cloth6 cloth_back
#define cloth7 cloth_mask
#define cloth8 cloth_necklace

struct PlayerInfo {
	bool isIn = false;
	int netID;
	bool haveGrowId = false;
	string tankIDName = "";
	string tankIDPass = "";
	string requestedName = "";
	string rawName = "";
	string displayName = "";
	string country = "";
	int adminLevel = 0;
	string currentWorld = "EXIT";
	bool radio = true;
	int x;
	int y;
	int x1;
	int y1;
	bool isRotatedLeft = false;
	string charIP = "";
	bool isUpdating = false;
	bool joinClothesUpdated = false;
	
	bool hasLogon = false;
	
	bool taped = false;

	int cloth_hair = 0; // 0
	int cloth_shirt = 0; // 1
	int cloth_pants = 0; // 2
	int cloth_feet = 0; // 3
	int cloth_face = 0; // 4
	int cloth_hand = 0; // 5
	int cloth_back = 0; // 6
	int cloth_mask = 0; // 7
	int cloth_necklace = 0; // 8

	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
	bool isInvisible = false; // 4
	bool noHands = false; // 8
	bool noEyes = false; // 16
	bool noBody = false; // 32
	bool devilHorns = false; // 64
	bool goldenHalo = false; // 128
	bool isFrozen = false; // 2048
	bool isCursed = false; // 4096
	bool isDuctaped = false; // 8192
	bool haveCigar = false; // 16384
	bool isShining = false; // 32768
	bool isZombie = false; // 65536
	bool isHitByLava = false; // 131072
	bool haveHauntedShadows = false; // 262144
	bool haveGeigerRadiation = false; // 524288
	bool haveReflector = false; // 1048576
	bool isEgged = false; // 2097152
	bool havePineappleFloag = false; // 4194304
	bool haveFlyingPineapple = false; // 8388608
	bool haveSuperSupporterName = false; // 16777216
	bool haveSupperPineapple = false; // 33554432
	bool isGhost = false;
	int skinColor = 0x8295C3FF; //normal SKin color like gt!

	PlayerInventory inventory;

	long long int lastSB = 0;
};


int getState(PlayerInfo* info) {
	int val = 0;
	val |= info->canWalkInBlocks << 0;
	val |= info->canDoubleJump << 1;
	val |= info->isInvisible << 2;
	val |= info->noHands << 3;
	val |= info->noEyes << 4;
	val |= info->noBody << 5;
	val |= info->devilHorns << 6;
	val |= info->goldenHalo << 7;
	val |= info->isFrozen << 11;
	val |= info->isCursed << 12;
	val |= info->isDuctaped << 13;
	val |= info->haveCigar << 14;
	val |= info->isShining << 15;
	val |= info->isZombie << 16;
	val |= info->isHitByLava << 17;
	val |= info->haveHauntedShadows << 18;
	val |= info->haveGeigerRadiation << 19;
	val |= info->haveReflector << 20;
	val |= info->isEgged << 21;
	val |= info->havePineappleFloag << 22;
	val |= info->haveFlyingPineapple << 23;
	val |= info->haveSuperSupporterName << 24;
	val |= info->haveSupperPineapple << 25;
	return val;
}


struct WorldItem {
	__int16 foreground = 0;
	__int16 background = 0;
	int breakLevel = 0;
	long long int breakTime = 0;
	bool water = false;
	bool fire = false;
	bool glue = false;
	bool red = false;
	bool green = false;
	bool blue = false;

};

struct WorldInfo {
	int width = 100;
	int height = 60;
	string name = "TEST";
	WorldItem* items;
	string owner = "";
	bool isPublic=false;
};

WorldInfo generateWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)){ world.items[i].foreground = 10; }
		else if (i >= 3700 && i < 5400) {
			if(i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 4;}
				else { world.items[i].foreground = 2; }
			}
			else { world.items[i].foreground = 2; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 14;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i<3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}

class PlayerDB {
public:
	static string getProperName(string name);
	static string fixColors(string text);
	static int playerLogin(ENetPeer* peer, string username, string password);
	static int playerRegister(string username, string password, string passwordverify, string email, string discord);
};

string PlayerDB::getProperName(string name) {
	string newS;
	for (char c : name) newS+=(c >= 'A' && c <= 'Z') ? c-('A'-'a') : c;
	string ret;
	for (int i = 0; i < newS.length(); i++)
	{
		if (newS[i] == '`') i++; else ret += newS[i];
	}
	string ret2;
	for (char c : ret) if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ret2 += c;
	
	string username = ret2;
	if (username == "prn" || username == "con" || username == "aux" || username == "nul" || username == "com1" || username == "com2" || username == "com3" || username == "com4" || username == "com5" || username == "com6" || username == "com7" || username == "com8" || username == "com9" || username == "lpt1" || username == "lpt2" || username == "lpt3" || username == "lpt4" || username == "lpt5" || username == "lpt6" || username == "lpt7" || username == "lpt8" || username == "lpt9") {
		return "";
	}
	
	return ret2;
}

string PlayerDB::fixColors(string text) {
	string ret = "";
	int colorLevel = 0;
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] == '`')
		{
			ret += text[i];
			if (i + 1 < text.length())
				ret += text[i + 1];
			
			
			if (i+1 < text.length() && text[i + 1] == '`')
			{
				colorLevel--;
			}
			else {
				colorLevel++;
			}
			i++;
		} else {
			ret += text[i];
		}
	}
	for (int i = 0; i < colorLevel; i++) {
		ret += "``";
	}
	for (int i = 0; i > colorLevel; i--) {
		ret += "`w";
	}
	return ret;
}

struct Admin {
	string username;
	string password;
	int level = 0;
	long long int lastSB = 0;
};

vector<Admin> admins;

PlayerInfo* playerInfo(ENetPeer* peer) {
    return (PlayerInfo*)(peer->data);
}

int PlayerDB::playerLogin(ENetPeer* peer, string username, string password) {
	std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		string pss = j["password"];
		int adminLevel = j["adminLevel"];
		if (verifyPassword(password, pss)) {
		    playerInfo(peer)->hasLogon = true;
			//after verify password add adminlevel not before
			bool found = false;
			for (int i = 0; i < admins.size(); i++) {
				if (admins[i].username == username) {
				found = true;	
				}
			}
			if (!found) {//not in vector
				if (adminLevel != 0) {
					Admin admin;
					admin.username = PlayerDB::getProperName(username);
					admin.password = pss;
					admin.level = adminLevel;
					admins.push_back(admin);
				}
			}
			ENetPeer * currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer == peer)
					continue;
				if ((playerInfo(currentPeer))->rawName == PlayerDB::getProperName(username))
				{
					{
						GamePacketBuilder()
							.appendString("OnConsoleMessage")
							.appendString("Someone else logged into this account!")
							.build()
							.send(currentPeer);

					}
					{
						GamePacketBuilder()
							.appendString("OnConsoleMessage")
							.appendString("Someone else was logged into this account! He was kicked out now.")
							.build()
							.send(peer);
					}
					enet_peer_disconnect_later(currentPeer, 0);
				}
			}
			return 1;
		}
		else {
			return -1;
		}
	}
	else {
		return -2;
	}
}

int PlayerDB::playerRegister(string username, string password, string passwordverify, string email, string discord) {
    string name = username;
    if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") return -1;
    username = PlayerDB::getProperName(username);
    if (discord.find("#") == std::string::npos && discord.length() != 0) return -5;
    if (email.find("@") == std::string::npos && email.length() != 0) return -4;
    if (passwordverify != password) return -3;
    if (username.length() < 3) return -2;
    std::ifstream ifs("players/" + username + ".json");
    if (ifs.is_open()) {
        return -1;
    }
	
	std::ofstream o("players/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	json j;
	j["username"] = username;
	j["password"] = hashPassword(password);
	j["email"] = email;
	j["discord"] = discord;
	j["adminLevel"] = 0;
	o << j << std::endl;
	return 1;
}

struct AWorld {
	WorldInfo* ptr;
	WorldInfo info;
	int id;
};

class WorldDB {
public:
	WorldInfo get(string name);
	AWorld get2(string name);
	void flush(WorldInfo info);
	void flush2(AWorld info);
	void save(AWorld info);
	void saveAll();
	void saveRedundant();
	vector<WorldInfo> getRandomWorlds();
	WorldDB();
private:
	vector<WorldInfo> worlds;
};

WorldDB::WorldDB() {
	// Constructor
}

namespace packet {
	void consoleMessage(ENetPeer* peer, string message) {

		GamePacketBuilder()
			.appendString("OnConsoleMessage")
			.appendString(message)
			.build()
			.send(peer);
	}
	void dialog(ENetPeer* peer, string message) {
		GamePacketBuilder()
			.appendString("OnDialogRequest")
			.appendString(message)
			.build()
			.send(peer);
	}
	void onSpawn(ENetPeer* peer, string message) {
		GamePacketBuilder()
			.appendString("OnSpawn")
			.appendString(message)
			.build()
			.send(peer);
	}
	void requestWorldSelectMenu(ENetPeer* peer, string message) {
		GamePacketBuilder()
			.appendString("OnRequestWorldSelectMenu")
			.appendString(message)
			.build()
			.send(peer);
	}

	void storeRequest(ENetPeer* peer, string message) {
		GamePacketBuilder()
			.appendString("OnStoreRequest")
			.appendString(message)
			.build()
			.send(peer);
	}
}

string getStrUpper(string txt) {
	string ret;
	for (char c : txt) ret += toupper(c);
	return ret;
}

AWorld WorldDB::get2(string name) {
	if (worlds.size() > 200) {
		cout << "Saving redundant worlds!" << endl;
		saveRedundant();
		cout << "Redundant worlds are saved!" << endl;
	}
	AWorld ret;
	name = getStrUpper(name);
	if (name.length() < 1) throw 1; // too short name
	for (char c : name) {
		if ((c<'A' || c>'Z') && (c<'0' || c>'9'))
			throw 2; // wrong name
	}
	if (name == "EXIT") {
		throw 3;
	}
	if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") throw 3;
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			ret.id = i;
			ret.info = worlds.at(i);
			ret.ptr = &worlds.at(i);
			return ret;
		}

	}
	std::ifstream ifs("worlds/" + name + ".json");
	if (ifs.is_open()) {

		json j;
		ifs >> j;
		WorldInfo info;
		info.name = j["name"].get<string>();
		info.width = j["width"];
		info.height = j["height"];
		info.owner = j["owner"].get<string>();
		info.isPublic = j["isPublic"];
		json tiles = j["tiles"];
		int square = info.width*info.height;
		info.items = new WorldItem[square];
		for (int i = 0; i < square; i++) {
			info.items[i].foreground = tiles[i]["fg"];
			info.items[i].background = tiles[i]["bg"];
		}
		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	else {
		WorldInfo info = generateWorld(name, 100, 60);

		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	throw 1;
}

WorldInfo WorldDB::get(string name) {

	return this->get2(name).info;
}

void WorldDB::flush(WorldInfo info)
{
	std::ofstream o("worlds/" + info.name + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
	}
	json j;
	j["name"] = info.name;
	j["width"] = info.width;
	j["height"] = info.height;
	j["owner"] = info.owner;
	j["isPublic"] = info.isPublic;
	json tiles = json::array();
	int square = info.width*info.height;
	
	for (int i = 0; i < square; i++)
	{
		json tile;
		tile["fg"] = info.items[i].foreground;
		tile["bg"] = info.items[i].background;
		tiles.push_back(tile);
	}
	j["tiles"] = tiles;
	o << j << std::endl;
}

void WorldDB::flush2(AWorld info)
{
	this->flush(info.info);
}

void WorldDB::save(AWorld info)
{
	flush2(info);
	delete info.info.items;
	worlds.erase(worlds.begin() + info.id);
}

void WorldDB::saveAll()
{
	for (int i = 0; i < worlds.size(); i++) {
		flush(worlds.at(i));
		delete worlds.at(i).items;
	}
	worlds.clear();
}

vector<WorldInfo> WorldDB::getRandomWorlds() {
	vector<WorldInfo> ret;
	for (int i = 0; i < ((worlds.size() < 10) ? worlds.size() : 10); i++)
	{ // load first four worlds, it is excepted that they are special
		ret.push_back(worlds.at(i));
	}
	// and lets get up to 6 random
	if (worlds.size() > 4) {
		for (int j = 0; j < 6; j++)
		{
			bool isPossible = true;
			WorldInfo world = worlds.at(rand() % (worlds.size() - 4));
			for (int i = 0; i < ret.size(); i++)
			{
				if (world.name == ret.at(i).name || world.name == "EXIT")
				{
					isPossible = false;
				}
			}
			if (isPossible)
				ret.push_back(world);
		}
	}
	return ret;
}

void WorldDB::saveRedundant()
{
	for (int i = 4; i < worlds.size(); i++) {
		bool canBeFree = true;
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if ((playerInfo(currentPeer))->currentWorld == worlds.at(i).name)
				canBeFree = false;
		}
		if (canBeFree)
		{
			flush(worlds.at(i));
			delete worlds.at(i).items;
			worlds.erase(worlds.begin() + i);
			i--;
		}
	}
}

//WorldInfo world;
//vector<WorldInfo> worlds;
WorldDB worldDB;

void saveAllWorlds() // atexit hack plz fix
{
	cout << "Saving worlds..." << endl;
	enet_host_destroy(server);
	worldDB.saveAll();
	cout << "Worlds saved!" << endl;
}

WorldInfo* getPlyersWorld(ENetPeer* peer)
{
	try {
		return worldDB.get2((playerInfo(peer))->currentWorld).ptr;
	} catch(int e) {
		return NULL;
	}
}

struct PlayerMoving {
	int packetType;
	int netID;
	float x;
	float y;
	int characterState;
	int plantingTree;
	float XSpeed;
	float YSpeed;
	int punchX;
	int punchY;

};


enum ClothTypes {
	HAIR,
	SHIRT,
	PANTS,
	FEET,
	FACE,
	HAND,
	BACK,
	MASK,
	NECKLACE,
	ANCES,
	NONE
};

enum BlockTypes {
	FOREGROUND,
	BACKGROUND,
	SEED,
	PAIN_BLOCK,
	BEDROCK,
	MAIN_DOOR,
	SIGN,
	DOOR,
	CLOTHING,
	FIST,
	CONSUMMABLE,
	CHECKPOINT,
	GATEWAY,
	LOCK,
	WEATHER_MACHINE,
	JAMMER,
	GEM,
	BOARD,
	UNKNOWN
};


struct ItemDefinition {
	int id;

	unsigned char editableType = 0;
	unsigned char itemCategory = 0;
	unsigned char actionType = 0;
	unsigned char hitSoundType = 0;

	string name;

	string texture = "";
	int textureHash = 0;
	unsigned char itemKind = 0;
	int val1;
	unsigned char textureX = 0;
	unsigned char textureY = 0;
	unsigned char spreadType = 0;
	unsigned char isStripeyWallpaper = 0;
	unsigned char collisionType = 0;

	unsigned char breakHits = 0;

	int dropChance = 0;
	unsigned char clothingType = 0;
	BlockTypes blockType;
	int growTime;
	ClothTypes clothType;
	int rarity;
	unsigned char maxAmount = 0;
	string extraFile = "";
	int extraFileHash = 0;
	int audioVolume = 0;
	string petName = "";
	string petPrefix = "";
	string petSuffix = "";
	string petAbility = "";
	unsigned	char seedBase = 0;
	unsigned	char seedOverlay = 0;
	unsigned	char treeBase = 0;
	unsigned	char treeLeaves = 0;
	int seedColor = 0;
	int seedOverlayColor = 0;
	bool isMultiFace = false;
	short val2;
	short isRayman = 0;
	string extraOptions = "";
	string texture2 = "";
	string extraOptions2 = "";
	string punchOptions = "";
	string description = "Nothing to see.";
};

vector<ItemDefinition> itemDefs;

struct DroppedItem { // TODO
	int id;
	int uid;
	int count;
};

vector<DroppedItem> droppedItems;

ItemDefinition getItemDef(int id)
{
	if (id < itemDefs.size() && id > -1)
		return itemDefs.at(id);

	throw 0;
	return itemDefs.at(0);
}

void craftItemDescriptions() {
	int current = -1;
	std::ifstream infile("Descriptions.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 3 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			if (atoi(ex[0].c_str()) + 1 < itemDefs.size())
			{
				itemDefs.at(atoi(ex[0].c_str())).description = ex[1];
				if (!(atoi(ex[0].c_str()) % 2))
					itemDefs.at(atoi(ex[0].c_str()) + 1).description = "This is a tree.";
			}
		}
	}
}

std::ifstream::pos_type filesize(const char* filename)
{
	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	return in.tellg();
}

uint32_t HashString(unsigned char* str, int len)
{
	if (!str) return 0;

	unsigned char* n = (unsigned char*)str;
	uint32_t acc = 0x55555555;

	if (len == 0)
	{
		while (*n)
			acc = (acc >> 27) + (acc << 5) + *n++;
	}
	else
	{
		for (int i = 0; i < len; i++)
		{
			acc = (acc >> 27) + (acc << 5) + *n++;
		}
	}
	return acc;

}

unsigned char* getA(string fileName, int* pSizeOut, bool bAddBasePath, bool bAutoDecompress)
{
	unsigned char* pData = NULL;
	FILE* fp = fopen(fileName.c_str(), "rb");
	if (!fp)
	{
		cout << "File not found" << endl;
		if (!fp) return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*pSizeOut = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pData = (unsigned char*)new unsigned char[((*pSizeOut) + 1)];
	if (!pData)
	{
		printf("Out of memory opening %s?", fileName.c_str());
		return 0;
	}
	pData[*pSizeOut] = 0;
	fread(pData, *pSizeOut, 1, fp);
	fclose(fp);

	return pData;
}

int itemdathash;
void buildItemsDatabase()
{
	string secret = "PBG892FXX982ABC*";
	std::ifstream file("items.dat", std::ios::binary | std::ios::ate);
	int size = file.tellg();
	char* data = new char[size];
	file.seekg(0, std::ios::beg);

	if (file.read((char*)(data), size))
	{
		itemsDat = new BYTE[60 + size];
		string asdf = "0400000010000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(itemsDat + (i / 2), &x, 1);
			if (asdf.length() > 60 * 2) throw 0;
		}
		memcpy(itemsDat + 56, &size, 4);
		file.seekg(0, std::ios::beg);
		if (file.read((char*)(itemsDat + 60), size))
		{
			uint8_t* pData;
			int size = 0;
			const char filename[] = "items.dat";
			size = filesize(filename);
			pData = getA((string)filename, &size, false, false);
			cout << "Updating items data success! Hash: " << HashString((unsigned char*)pData, size) << endl;
			itemdathash = HashString((unsigned char*)pData, size);
			file.close();
		}
	}
	else {
		cout << "Updating items data failed!" << endl;
		exit(0);
	}
	int itemCount;
	int memPos = 0;
	int16_t itemsdatVersion = 0;
	memcpy(&itemsdatVersion, data + memPos, 2);
	memPos += 2;
	memcpy(&itemCount, data + memPos, 4);
	memPos += 4; 
	for (int i = 0; i < itemCount; i++) { 
		ItemDefinition tile; 

		{
			memcpy(&tile.id, data + memPos, 4);
			memPos += 4;
		}
		{
			tile.editableType = data[memPos];
			memPos += 1;
		}
		{
			tile.itemCategory = data[memPos];
			memPos += 1;
		}
		{
			tile.actionType = data[memPos];
			memPos += 1;
		}
		{
			tile.hitSoundType = data[memPos];
			memPos += 1;
		}
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.name += data[memPos] ^ (secret[(j + tile.id) % secret.length()]);

				memPos++;
			}
		}
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.texture += data[memPos];
				memPos++;
			}
		}
		memcpy(&tile.textureHash, data + memPos, 4);
		memPos += 4;
		tile.itemKind = memPos[data];
		memPos += 1;
		memcpy(&tile.val1, data + memPos, 4);
		memPos += 4;
		tile.textureX = data[memPos];
		memPos += 1;
		tile.textureY = data[memPos];
		memPos += 1;
		tile.spreadType = data[memPos];
		memPos += 1;
		tile.isStripeyWallpaper = data[memPos];
		memPos += 1;
		tile.collisionType = data[memPos];
		memPos += 1;
		tile.breakHits = data[memPos] / 6;
		memPos += 1;
		memcpy(&tile.dropChance, data + memPos, 4);
		memPos += 4;
		tile.clothingType = data[memPos];
		memPos += 1;
		memcpy(&tile.rarity, data + memPos, 2);
		memPos += 2;
		tile.maxAmount = data[memPos];
		memPos += 1;
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.extraFile += data[memPos];
				memPos++;
			}
		}
		memcpy(&tile.extraFileHash, data + memPos, 4);
		memPos += 4;
		memcpy(&tile.audioVolume, data + memPos, 4);
		memPos += 4;
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.petName += data[memPos];
				memPos++;
			}
		}
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.petPrefix += data[memPos];
				memPos++;
			}
		}
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.petSuffix += data[memPos];
				memPos++;
			}
		}
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.petAbility += data[memPos];
				memPos++;
			}
		}
		{
			tile.seedBase = data[memPos];
			memPos += 1;
		}
		{
			tile.seedOverlay = data[memPos];
			memPos += 1;
		}
		{
			tile.treeBase = data[memPos];
			memPos += 1;
		}
		{
			tile.treeLeaves = data[memPos];
			memPos += 1;
		}
		{
			memcpy(&tile.seedColor, data + memPos, 4);
			memPos += 4;
		}
		{
			memcpy(&tile.seedOverlayColor, data + memPos, 4);
			memPos += 4;
		}
		memPos += 4; // deleted ingredients
		{
			memcpy(&tile.growTime, data + memPos, 4);
			memPos += 4;
		}
		memcpy(&tile.val2, data + memPos, 2);
		memPos += 2;
		memcpy(&tile.isRayman, data + memPos, 2);
		memPos += 2;
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.extraOptions += data[memPos];
				memPos++;
			}
		}
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.texture2 += data[memPos];
				memPos++;
			}
		}
		{
			int16_t strLen = *(int16_t*)&data[memPos];
			memPos += 2;
			for (int j = 0; j < strLen; j++) {
				tile.extraOptions2 += data[memPos];
				memPos++;
			}
		}
		memPos += 80;
		if (itemsdatVersion >= 11) {
			{
				int16_t strLen = *(int16_t*)&data[memPos];
				memPos += 2;
				for (int j = 0; j < strLen; j++) {
					tile.punchOptions += data[memPos];
					memPos++;
				}
			}
		}
		if (i != tile.id)
			cout << "Item are unordered!" << i << "/" << tile.id << endl;

		switch (tile.actionType) {
		case 0:
			tile.blockType = BlockTypes::FIST;
			break;
		case 1:
			// wrench tool
			break;
		case 2:
			tile.blockType = BlockTypes::DOOR;
			break;
		case 3:
			tile.blockType = BlockTypes::LOCK;
			break;
		case 4:
			tile.blockType = BlockTypes::GEM;
			break;
		case 8:
			tile.blockType = BlockTypes::CONSUMMABLE;
			break;
		case 9:
			tile.blockType = BlockTypes::GATEWAY;
			break;
		case 10:
			tile.blockType = BlockTypes::SIGN;
			break;
		case 13:
			tile.blockType = BlockTypes::MAIN_DOOR;
			break;
		case 15:
			tile.blockType = BlockTypes::BEDROCK;
			break;
		case 17:
			tile.blockType = BlockTypes::FOREGROUND;
			break;
		case 18:
			tile.blockType = BlockTypes::BACKGROUND;
			break;
		case 19:
			tile.blockType = BlockTypes::SEED;
			break;
		case 20:
			tile.blockType = BlockTypes::CLOTHING; 
				switch(tile.clothingType){
					case 0: tile.clothType = ClothTypes::HAIR;
						break;
					case 1: tile.clothType = ClothTypes::SHIRT;
						break;
					case 2: tile.clothType = ClothTypes::PANTS;
						break;
					case 3: tile.clothType = ClothTypes::FEET;
						break; 
					case 4: tile.clothType = ClothTypes::FACE;
						break;
					case 5: tile.clothType = ClothTypes::HAND;
						break;
					case 6: tile.clothType = ClothTypes::BACK;
						break;
					case 7: tile.clothType = ClothTypes::MASK;
						break;
					case 8: tile.clothType = ClothTypes::NECKLACE;
						break;
						
				} 

			break;
		case 26: // portal
			tile.blockType = BlockTypes::DOOR;
			break;
		case 27:
			tile.blockType = BlockTypes::CHECKPOINT;
			break;
		case 28: // piano note
			tile.blockType = BlockTypes::BACKGROUND;
			break;
		case 41:
			tile.blockType = BlockTypes::WEATHER_MACHINE;
			break;
		case 34: // bulletin boardd
			tile.blockType = BlockTypes::BOARD;
			break;
		case 107: // ances
			tile.blockType = BlockTypes::CLOTHING;
			tile.clothType = ClothTypes::ANCES;
			break;
		default:
			 break;

		}
 

		// -----------------
		itemDefs.push_back(tile);
	} 
	craftItemDescriptions();
}

void addAdmin(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}

int getAdminLevel(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level;
		}
	}
	return 0;
}

bool canSB(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level>1) {
			using namespace std::chrono;
			if (admin.lastSB + 900000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
			{
				admins[i].lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				return true;
			}
			else {
				return false;
			}
		}
	}
	return false;
}

bool canClear(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level > 0;
		}
	}
	return false;
}

bool isSuperAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 999) {
			return true;
		}
	}
	return false;
}

bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return (playerInfo(peer))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}

void sendInventory(ENetPeer* peer, PlayerInventory inventory)
{
	string asdf2 = "0400000009A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000000000000000";
	int inventoryLen = inventory.items.size();
	int packetLen = (asdf2.length() / 2) + (inventoryLen * 4) + 4;
	BYTE* data2 = new BYTE[packetLen];
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int endianInvVal = _byteswap_ulong(inventoryLen);
	memcpy(data2 + (asdf2.length() / 2) - 4, &endianInvVal, 4);
	endianInvVal = _byteswap_ulong(inventory.inventorySize);
	memcpy(data2 + (asdf2.length() / 2) - 8, &endianInvVal, 4);
	int val = 0;
	for (int i = 0; i < inventoryLen; i++)
	{
		val = 0;
		val |= inventory.items.at(i).itemID;
		val |= inventory.items.at(i).itemCount << 16;
		val &= 0x00FFFFFF;
		val |= 0x00 << 24;
		memcpy(data2 + (i*4) + (asdf2.length() / 2), &val, 4);
	}
	ENetPacket * packet3 = enet_packet_create(data2,
		packetLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete[] data2;
	//enet_host_flush(server);
}

BYTE* packPlayerMoving(PlayerMoving* dataStruct)
{
	BYTE* data = new BYTE[56];
	for (int i = 0; i < 56; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 4, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 20, &dataStruct->plantingTree, 4);
	memcpy(data + 24, &dataStruct->x, 4);
	memcpy(data + 28, &dataStruct->y, 4);
	memcpy(data + 32, &dataStruct->XSpeed, 4);
	memcpy(data + 36, &dataStruct->YSpeed, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	return data;
}

PlayerMoving* unpackPlayerMoving(BYTE* data)
{
	PlayerMoving* dataStruct = new PlayerMoving;
	memcpy(&dataStruct->packetType, data, 4);
	memcpy(&dataStruct->netID, data + 4, 4);
	memcpy(&dataStruct->characterState, data + 12, 4);
	memcpy(&dataStruct->plantingTree, data + 20, 4);
	memcpy(&dataStruct->x, data + 24, 4);
	memcpy(&dataStruct->y, data + 28, 4);
	memcpy(&dataStruct->XSpeed, data + 32, 4);
	memcpy(&dataStruct->YSpeed, data + 36, 4);
	memcpy(&dataStruct->punchX, data + 44, 4);
	memcpy(&dataStruct->punchY, data + 48, 4);
	return dataStruct;
}

void SendPacket(int a1, string a2, ENetPeer* enetPeer)
{
	if (enetPeer)
	{
		ENetPacket* v3 = enet_packet_create(0, a2.length() + 5, 1);
		memcpy(v3->data, &a1, 4);
		//*(v3->data) = (DWORD)a1;
		memcpy((v3->data) + 4, a2.c_str(), a2.length());

		//cout << std::hex << (int)(char)v3->data[3] << endl;
		enet_peer_send(enetPeer, 0, v3);
	}
}

void SendPacketRaw(int a1, void *packetData, size_t packetDataSize, void *a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket *p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE *)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD *)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			memcpy((char *)p->data + packetDataSize + 4, a4, *((DWORD *)packetData + 13));
			enet_peer_send(peer, 0, p);
		}
		else
		{
			p = enet_packet_create(0, packetDataSize + 5, packetFlag);
			memcpy(p->data, &a1, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			enet_peer_send(peer, 0, p);
		}
	}
	delete (char*)packetData;
}


	void onPeerConnect(ENetPeer* peer)
	{
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (peer != currentPeer)
			{
				if (isHere(peer, currentPeer))
				{
					string netIdS = std::to_string((playerInfo(currentPeer))->netID);
					packet::onSpawn(peer, "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + netIdS + "\ncolrect|0|0|20|30\nposXY|" + std::to_string((playerInfo(currentPeer))->x) + "|" + std::to_string((playerInfo(currentPeer))->y) + "\nname|``" + (playerInfo(currentPeer))->displayName + "``\ncountry|" + (playerInfo(currentPeer))->country + "\ninvis|0\nmstate|0\nsmstate|0\n"); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
					string netIdS2 = std::to_string((playerInfo(peer))->netID);
					packet::onSpawn(currentPeer, "spawn|avatar\nnetID|" + netIdS2 + "\nuserID|" + netIdS2 + "\ncolrect|0|0|20|30\nposXY|" + std::to_string((playerInfo(peer))->x) + "|" + std::to_string((playerInfo(peer))->y) + "\nname|``" + (playerInfo(peer))->displayName + "``\ncountry|" + (playerInfo(peer))->country + "\ninvis|0\nmstate|0\nsmstate|0\n"); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
				}
			}
		}
		
	}

	void updateAllClothes(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				GamePacket p3 = GamePacketBuilder()
					.appendString("OnSetClothing")
					.appendFloat(playerInfo(peer)->cloth_hair, playerInfo(peer)->cloth_shirt, playerInfo(peer)->cloth_pants)
					.appendFloat(playerInfo(peer)->cloth_feet, playerInfo(peer)->cloth_face, playerInfo(peer)->cloth_hand)
					.appendFloat(playerInfo(peer)->cloth_back, playerInfo(peer)->cloth_mask, (playerInfo(peer))->cloth_necklace)
					.appendIntx(playerInfo(peer)->skinColor)
					.appendFloat(0.0f, 0.0f, 0.0f)
					.build();

				memcpy(p3.data + 8, &((playerInfo(peer))->netID), 4); // ffloor
				p3.send(currentPeer);

				//enet_host_flush(server);
				GamePacket p4 = GamePacketBuilder()
					.appendString("OnSetClothing")
					.appendFloat(playerInfo(peer)->cloth_hair, playerInfo(peer)->cloth_shirt, playerInfo(peer)->cloth_pants)
					.appendFloat(playerInfo(peer)->cloth_feet, playerInfo(peer)->cloth_face, playerInfo(peer)->cloth_hand)
					.appendFloat(playerInfo(peer)->cloth_back, playerInfo(peer)->cloth_mask, (playerInfo(peer))->cloth_necklace)
					.appendIntx(playerInfo(peer)->skinColor)
					.appendFloat(0.0f, 0.0f, 0.0f)
					.build();

				memcpy(p4.data + 8, &((playerInfo(currentPeer))->netID), 4); // ffloor
				p4.send(peer);
				//enet_host_flush(server);
			}
		}
	}

	void sendClothes(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		GamePacket p3 = GamePacketBuilder()
			.appendString("OnSetClothing")
			.appendFloat(playerInfo(peer)->cloth_hair, playerInfo(peer)->cloth_shirt, playerInfo(peer)->cloth_pants)
			.appendFloat(playerInfo(peer)->cloth_feet, playerInfo(peer)->cloth_face, playerInfo(peer)->cloth_hand)
			.appendFloat(playerInfo(peer)->cloth_back, playerInfo(peer)->cloth_mask, (playerInfo(peer))->cloth_necklace)
			.appendIntx(playerInfo(peer)->skinColor)
			.appendFloat(0.0f, 0.0f, 0.0f)
			.build();
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				
				memcpy(p3.data + 8, &((playerInfo(peer))->netID), 4); // ffloor
				p3.send(currentPeer);
			}

		}
		//enet_host_flush(server);
	}

	void sendPData(ENetPeer* peer, PlayerMoving* data)
	{
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (peer != currentPeer)
			{
				if (isHere(peer, currentPeer))
				{
					data->netID = (playerInfo(peer))->netID;

					SendPacketRaw(4, packPlayerMoving(data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
				}
			}
		}
	}

	int getPlayersCountInWorld(string name)
	{
		int count = 0;
		ENetPeer * currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if ((playerInfo(currentPeer))->currentWorld == name)
				count++;
		}
		return count;
	}

	void sendRoulete(ENetPeer* peer, int x, int y)
	{
		ENetPeer* currentPeer;
		int val = rand() % 37;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				GamePacketBuilder()
					.appendString("OnTalkBubble")
					.appendIntx(playerInfo(peer)->netID)
					.appendString("`w[" + (playerInfo(peer))->displayName + " `wspun the wheel and got `6" + std::to_string(val) + "`w!]")
					.appendIntx(0)
					.build()
					.send(currentPeer);
			}
				

			//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
		}
	}


	void sendNothingHappened(ENetPeer* peer, int x, int y) {
		PlayerMoving data;
		data.netID = (playerInfo(peer))->netID;
		data.packetType = 0x8;
		data.plantingTree = 0;
		data.netID = -1;
		data.x = x;
		data.y = y;
		data.punchX = x;
		data.punchY = y;
		SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	}

void loadnews() {
	std::ifstream ifs("news.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));

	string target = "\r";
	string news = "";
	int found = -1;
	do {
		found = content.find(target, found + 1);
		if (found != -1) {
			news = content.substr(0, found) + content.substr(found + target.length());
		}
		else {
			news = content;
		}
	} while (found != -1);
	if(news != "") {
		newslist = news;
	}
}

	void sendTileUpdate(int x, int y, int tile, int causedBy, ENetPeer* peer)
	{
		if (tile > itemDefs.size()) {
			return;
		}
		PlayerMoving data;
		//data.packetType = 0x14;
		data.packetType = 0x3;

		//data.characterState = 0x924; // animation
		data.characterState = 0x0; // animation
		data.x = x;
		data.y = y;
		data.punchX = x;
		data.punchY = y;
		data.XSpeed = 0;
		data.YSpeed = 0;
		data.netID = causedBy;
		data.plantingTree = tile;
		
		WorldInfo *world = getPlyersWorld(peer);

		if (getItemDef(tile).blockType == BlockTypes::CONSUMMABLE) return;

		if (world == NULL) return;
		if (x<0 || y<0 || x>world->width - 1 || y>world->height - 1||tile > itemDefs.size()) return; // needs - 1
		sendNothingHappened(peer,x,y);
		if (!isSuperAdmin((playerInfo(peer))->rawName, (playerInfo(peer))->tankIDPass))
		{
			if (world->items[x + (y*world->width)].foreground == 6 || world->items[x + (y*world->width)].foreground == 8 || world->items[x + (y*world->width)].foreground == 3760)
				return;
			if (tile == 6 || tile == 8 || tile == 3760 || tile == 6864)
				return;
		}
		if (world->name == "ADMIN" && !getAdminLevel((playerInfo(peer))->rawName, (playerInfo(peer))->tankIDPass))
		{
			if (world->items[x + (y*world->width)].foreground == 758)
				sendRoulete(peer, x, y);
			return;
		}
		if (world->name != "ADMIN") {
			if (world->owner != "") {
				if ((playerInfo(peer))->rawName == world->owner) {
					// WE ARE GOOD TO GO
					if (tile == 32) {
						if (world->items[x + (y*world->width)].foreground == 242 or world->items[x + (y*world->width)].foreground == 202 or world->items[x + (y*world->width)].foreground == 204 or world->items[x + (y*world->width)].foreground == 206 or world->items[x + (y*world->width)].foreground == 2408 or world->items[x + (y*world->width)].foreground == 5980 or world->items[x + (y*world->width)].foreground == 2950 or world->items[x + (y*world->width)].foreground == 5814 or world->items[x + (y*world->width)].foreground == 4428 or world->items[x + (y*world->width)].foreground == 1796 or world->items[x + (y*world->width)].foreground == 4802 or world->items[x + (y*world->width)].foreground == 4994 or world->items[x + (y*world->width)].foreground == 5260 or world->items[x + (y*world->width)].foreground == 7188)
						{
							packet::dialog(peer, "set_default_color|`o\n\nadd_label_with_icon|big|`wShould this world be publicly breakable?``|left|242|\n\nadd_spacer|small|\nadd_button_with_icon|worldPublic|Public|noflags|2408||\nadd_button_with_icon|worldPrivate|Private|noflags|202||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nend_dialog|wl_edit|||"); // Added dialog name
						}
					}
				}
				else if (world->isPublic)
				{
					if (world->items[x + (y*world->width)].foreground == 242)
					{
						return;
					}
				}
				else {
					return;
				}
				if (tile == 242) {
					return;
				}
			}
		}
		if (tile == 32) {
			// TODO
			return;
		}
		if (tile == 822) {
			world->items[x + (y*world->width)].water = !world->items[x + (y*world->width)].water;
			return;
		}
		if (tile == 3062)
		{
			world->items[x + (y*world->width)].fire = !world->items[x + (y*world->width)].fire;
			return;
		}
		if (tile == 1866)
		{
			world->items[x + (y*world->width)].glue = !world->items[x + (y*world->width)].glue;
			return;
		}
		ItemDefinition def;
		try {
			def = getItemDef(tile);
			if (def.blockType == BlockTypes::CLOTHING) return;
		}
		catch (int e) {
			def.breakHits = 4;
			def.blockType = BlockTypes::UNKNOWN;
			cout << "Ugh, unsupported item " << tile << endl;
		}
 
		if (tile == 18) {
			if (world->items[x + (y*world->width)].background == 6864 && world->items[x + (y*world->width)].foreground == 0) return;
			if (world->items[x + (y*world->width)].background == 0 && world->items[x + (y*world->width)].foreground == 0) return;
			//data.netID = -1;
			data.packetType = 0x8;
			data.plantingTree = 4;
			using namespace std::chrono;
			//if (world->items[x + (y*world->width)].foreground == 0) return;
			if ((duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() - world->items[x + (y*world->width)].breakTime >= 4000)
			{
				world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				world->items[x + (y*world->width)].breakLevel = 4; // TODO
				if (world->items[x + (y*world->width)].foreground == 758)
					sendRoulete(peer, x, y);
			}
			else
				if (y < world->height && world->items[x + (y*world->width)].breakLevel + 4 >= def.breakHits * 4) { // TODO
					data.packetType = 0x3;// 0xC; // 0xF // World::HandlePacketTileChangeRequest
					data.netID = -1;
					data.plantingTree = 0;
					world->items[x + (y*world->width)].breakLevel = 0;
					if (world->items[x + (y*world->width)].foreground != 0)
					{
						if (world->items[x + (y*world->width)].foreground == 242)
						{
							world->owner = "";
							world->isPublic = false;
						}
						world->items[x + (y*world->width)].foreground = 0;
					}
					else {
						data.plantingTree = 6864;
						world->items[x + (y*world->width)].background = 6864;
					}
					
				}
				else
					if (y < world->height)
					{
						world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						world->items[x + (y*world->width)].breakLevel += 4; // TODO
						if (world->items[x + (y*world->width)].foreground == 758)
							sendRoulete(peer, x, y);
					}

		}
		else {
			for (int i = 0; i < (playerInfo(peer))->inventory.items.size(); i++)
			{
				if ((playerInfo(peer))->inventory.items.at(i).itemID == tile)
				{
					if ((unsigned int)(playerInfo(peer))->inventory.items.at(i).itemCount>1)
					{
						(playerInfo(peer))->inventory.items.at(i).itemCount--;
					}
					else {
						(playerInfo(peer))->inventory.items.erase((playerInfo(peer))->inventory.items.begin() + i);
						
					}
				}
			}
			if (def.blockType == BlockTypes::BACKGROUND)
			{
				world->items[x + (y*world->width)].background = tile;
			}
			else {
				if (world->items[x + (y * world->width)].foreground != 0)return;
				world->items[x + (y*world->width)].foreground = tile;
				if (tile == 242) {
					world->owner = (playerInfo(peer))->rawName;
					world->isPublic = false;
					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer)) {
							packet::consoleMessage(peer, "`3[`w" + world->name + " `ohas been World Locked by `2" + (playerInfo(peer))->displayName + "`3]");
						}
					}
				}
				
			}

			world->items[x + (y*world->width)].breakLevel = 0;
		}

		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
				SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			
			//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
		}
	}

	void sendPlayerLeave(ENetPeer* peer, PlayerInfo* player)
	{
		ENetPeer * currentPeer;
		GamePacket p = GamePacketBuilder()
			.appendString("OnRemove")
			.appendString("netID | " + std::to_string(player->netID) + "\n")
			.build();
		GamePacket p2 =
			GamePacketBuilder()
			.appendString("OnConsoleMessage")
			.appendString("`5<`w" + player->displayName + "`` left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`` others here>``")
			.build();

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				p.send(peer);
				p.send(currentPeer);
				p2.send(currentPeer);
			}
		}
	}

	static inline void ltrim(string &s)
	{
		s.erase(s.begin(), find_if(s.begin(), s.end(), [](int ch) {
			return !isspace(ch);
		}));
	}

	static inline void rtrim(string &s)
	{
		s.erase(find_if(s.rbegin(), s.rend(), [](int ch) {
			return !isspace(ch);
		}).base(), s.end());
	}

	static inline void trim(string &s)
	{
		ltrim(s);
		rtrim(s);
	}

	static inline string trimString(string s)
	{
    	trim(s);
    	return s;
	}

	int countSpaces(string& str)
	{ 
		int count = 0; 
		int length = str.length(); 
		for (int i = 0; i < length; i++)
		{ 
			int c = str[i]; 
			if (isspace(c)) 
				count++; 
		}
		return count; 
	} 
  
	void removeExtraSpaces(string &str) 
	{
		int n = str.length(); 
		int i = 0, j = -1; 
		bool spaceFound = false; 
		while (++j < n && str[j] == ' '); 
	
		while (j < n) 
		{ 
			if (str[j] != ' ') 
			{ 
				if ((str[j] == '.' || str[j] == ',' || 
					str[j] == '?') && i - 1 >= 0 && 
					str[i - 1] == ' ') 
					str[i - 1] = str[j++]; 
				else
					str[i++] = str[j++]; 

				spaceFound = false; 
			} 
 
			else if (str[j++] == ' ') 
			{
				if (!spaceFound) 
				{ 
					str[i++] = ' '; 
					spaceFound = true; 
				} 
			} 
		}
		if (i <= 1) 
        	str.erase(str.begin() + i, str.end()); 
    	else
        	str.erase(str.begin() + i, str.end()); 
	} 

	void sendChatMessage(ENetPeer* peer, int netID, string message)
	{
		if (message.length() == 0) return; 

		if (1 > (message.size() - countSpaces(message))) return;
		removeExtraSpaces(message);
		message = trimString(message);

		ENetPeer * currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if ((playerInfo(currentPeer))->netID == netID)
				name = (playerInfo(currentPeer))->displayName;

		}
		GamePacket p = GamePacketBuilder()
			.appendString("OnConsoleMessage")
			.appendString("CP:0_PL:4_OID:_CT:[W]_ `o<`w" + name + "`o> " + message)
			.build();
		GamePacket p2 = GamePacketBuilder()
			.appendString("OnTalkBubble")
			.appendIntx(netID)
			.appendString(message)
			.appendIntx(0)
			.build();
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				p.send(currentPeer);
				p2.send(currentPeer);
			}
		}
	}

	void sendWho(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				if ((playerInfo(currentPeer))->isGhost) {
					continue;
				}
				GamePacketBuilder()
					.appendString("OnTalkBubble")
					.appendIntx(playerInfo(currentPeer)->netID)
					.appendString(playerInfo(currentPeer)->displayName)
					.appendIntx(1)
					.build()
					.send(peer);
				//enet_host_flush(server);
			}
		}
	}

	void sendWorld(ENetPeer* peer, WorldInfo* worldInfo)
	{
		cout << "Entering a world..." << endl;
		(playerInfo(peer))->joinClothesUpdated = false;
		
		 string worldName = worldInfo->name; 
		int xSize = worldInfo->width;
		int ySize = worldInfo->height;
		int square = xSize*ySize; 
		__int16 namelen = worldName.length();
		
		int alloc = (8 * square);
	        int total = 78 + namelen + square + 24 + alloc     ;
		
		BYTE* data = new BYTE[total];
		int s1 = 4,s3 = 8,zero = 0;  
		 
		 memset(data, 0, total);

		 memcpy(data, &s1, 1);
		 memcpy(data + 4, &s1, 1);
		 memcpy(data + 16, &s3, 1);  
		 memcpy(data + 66, &namelen, 1);
		 memcpy(data + 68, worldName.c_str(), namelen);
		 memcpy(data + 68 + namelen, &xSize, 1);
		 memcpy(data + 72 + namelen, &ySize, 1);
		 memcpy(data + 76 + namelen, &square, 2);
		 BYTE* blc = data + 80 + namelen;
		for (int i = 0; i < square; i++) {
			//removed cus some of blocks require tile extra and it will crash the world without
			memcpy(blc, &zero, 2);
			
			memcpy(blc + 2, &worldInfo->items[i].background, 2);
			int type = 0x00000000;
			// type 1 = locked
			if (worldInfo->items[i].water)
				type |= 0x04000000;
			if (worldInfo->items[i].glue)
				type |= 0x08000000;
			if (worldInfo->items[i].fire)
				type |= 0x10000000;
			if (worldInfo->items[i].red)
				type |= 0x20000000;
			if (worldInfo->items[i].green)
				type |= 0x40000000;
			if (worldInfo->items[i].blue)
				type |= 0x80000000;

			// int type = 0x04000000; = water
			// int type = 0x08000000 = glue
			// int type = 0x10000000; = fire
			// int type = 0x20000000; = red color
			// int type = 0x40000000; = green color
			// int type = 0x80000000; = blue color
			memcpy(blc + 4, &type, 4);
			blc += 8;
		}
		
		//int totalitemdrop = worldInfo->dropobject.size();
	        //memcpy(blc, &totalitemdrop, 2);
		
		ENetPacket* packetw = enet_packet_create(data, total, ENET_PACKET_FLAG_RELIABLE);
	        enet_peer_send(peer, 0, packetw);
		
		
		for (int i = 0; i < square; i++) {
				PlayerMoving data;
				//data.packetType = 0x14;
				data.packetType = 0x3;

				//data.characterState = 0x924; // animation
				data.characterState = 0x0; // animation
				data.x = i%worldInfo->width;
				data.y = i/worldInfo->height;
				data.punchX = i%worldInfo->width;
				data.punchY = i / worldInfo->width;
				data.XSpeed = 0;
				data.YSpeed = 0;
				data.netID = -1;
				data.plantingTree = worldInfo->items[i].foreground;
				SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
		}
		(playerInfo(peer))->currentWorld = worldInfo->name;
		if (worldInfo->owner != "") {
			packet::consoleMessage(peer, "`#[`0" + worldInfo->name + " `9World Locked by " + worldInfo->owner + "`#]");
		}
		delete[] data;

	}

	void sendAction(ENetPeer* peer, int netID, string action)
	{
		ENetPeer * currentPeer;
		string name = "";
		GamePacket p2 = GamePacketBuilder()
			.appendString("OnAction")
			.appendString(action)
			.build();
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				memcpy(p2.data + 8, &netID, 4);
				p2.send(currentPeer);
			}
		}
	}


	// droping items WorldObjectMap::HandlePacket
	void sendDrop(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect)
	{
		if (item >= 7068) return;
		if (item < 0) return;
		ENetPeer * currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				PlayerMoving data;
				data.packetType = 14;
				data.x = x;
				data.y = y;
				data.netID = netID;
				data.plantingTree = item;
				float val = count; // item count
				BYTE val2 = specialEffect;

				BYTE* raw = packPlayerMoving(&data);
				memcpy(raw + 16, &val, 4);
				memcpy(raw + 1, &val2, 1);

				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}

	void sendState(ENetPeer* peer) {
		//return; // TODO
		PlayerInfo* info = (playerInfo(peer));
		int netID = info->netID;
		ENetPeer * currentPeer;
		int state = getState(info);
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				PlayerMoving data;
				data.packetType = 0x14;
				data.characterState = 0; // animation
				data.x = 1000;
				data.y = 100;
				data.punchX = 0;
				data.punchY = 0;
				data.XSpeed = 300;
				data.YSpeed = 600;
				data.netID = netID;
				data.plantingTree = state;
				BYTE* raw = packPlayerMoving(&data);
				int var = 0x808000; // placing and breking
				memcpy(raw+1, &var, 3);
				float waterspeed = 125.0f;
				memcpy(raw + 16, &waterspeed, 4);
				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
		// TODO
	}

	

	void sendWorldOffers(ENetPeer* peer)
	{
		if (!(playerInfo(peer))->isIn) return;
		vector<WorldInfo> worlds = worldDB.getRandomWorlds();
		string worldOffers = "default|";
		if (worlds.size() > 0) {
			worldOffers += worlds[0].name;
		}
		
		worldOffers += "\nadd_button|Showing: `wWorlds``|_catselect_|0.6|3529161471|\n";
		for (int i = 0; i < worlds.size(); i++) {
			worldOffers += "add_floater|"+worlds[i].name+"|"+std::to_string(getPlayersCountInWorld(worlds[i].name))+"|0.55|3529161471\n";
		}
		//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
		//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
		packet::requestWorldSelectMenu(peer, worldOffers);
	}




	//replaced X-to-close with a Ctrl+C exit
	void exitHandler(int s) {
		saveAllWorlds();
		exit(0);

	}

void loadConfig() {
	std::ifstream ifs("config.json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		ifs.close();
		try {
			configPort = j["port"].get<int>();
			configCDN = j["cdn"].get<string>();
			
			cout << "Config loaded." << endl;
		} catch (...) {
			cout << "Invalid config." << endl;
		}
	} else {
		cout << "Config not found." << endl;
	}
}

string randomDuctTapeMessage (size_t length) {
	auto randchar = []() -> char
    {
        const char charset[] =
        "f"
        "m";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
    };
    std::string str(length,0);
    std::generate_n(str.begin(), length, randchar );
    return str;
}
	/*
	action|log
msg|`4UPDATE REQUIRED!`` : The `$V2.981`` update is now available for your device.  Go get it!  You'll need to install it before you can play online.
[DBG] Some text is here: action|set_url
url|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exe
label|Download Latest Version
	*/
//Linux should not have any arguments in main function.
#ifdef _WIN32
	int _tmain(int argc, _TCHAR* argv[])
#else
	int main()
#endif
{
	cout << "Growtopia private server (c) Growtopia Noobs" << endl;
		
	cout << "Loading config from config.json" << endl;
	loadConfig();
		
	enet_initialize();
	signal(SIGINT, exitHandler);
	worldDB.get("TEST");
	worldDB.get("MAIN");
	worldDB.get("NEW");
	worldDB.get("ADMIN");
	ENetAddress address;
	/* Bind the server to the default localhost.     */
	/* A specific host address can be specified by   */
	enet_address_set_host (&address, "0.0.0.0");
	//address.host = ENET_HOST_ANY;
	/* Bind the server to port 1234. */
	address.port = configPort;
	server = enet_host_create(&address /* the address to bind the server host to */,
		1024      /* allow up to 32 clients and/or outgoing connections */,
		10      /* allow up to 2 channels to be used, 0 and 1 */,
		0      /* assume any amount of incoming bandwidth */,
		0      /* assume any amount of outgoing bandwidth */);
	if (server == NULL)
	{
		fprintf(stderr,
			"An error occurred while trying to create an ENet server host.\n");
		while (1);
		exit(EXIT_FAILURE);
	}
	server->checksum = enet_crc32;
	enet_host_compress_with_range_coder(server);

	cout << "Building items database..." << endl;
	buildItemsDatabase();
	cout << "Database is built!" << endl;
	loadnews();

	ENetEvent event;
	/* Wait up to 1000 milliseconds for an event. */
	while (enet_host_service(server, &event, 1000) > 0)
	{
		ENetPeer* peer = event.peer;
		switch (event.type)
		{
		case ENET_EVENT_TYPE_CONNECT:
		{
			printf("A new client connected.\n");
			/* Store any relevant client information here. */
			ENetPeer * currentPeer;
			int count = 0;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer->address.host == peer->address.host)
					count++;
			}

			event.peer->data = new PlayerInfo;
			/* Get the string ip from peer */
			char clientConnection[16];
			enet_address_get_host_ip(&peer->address, clientConnection, 16);
			(playerInfo(peer))->charIP = clientConnection;
			if (count > 3)
			{
				packet::consoleMessage(peer, "`rToo many accounts are logged on from this IP. Log off one account before playing please.``");
				enet_peer_disconnect_later(peer, 0);
			}
			else {
				sendData(peer, 1, 0, 0);
			}


			continue;
		}
		case ENET_EVENT_TYPE_RECEIVE:
		{
			if ((playerInfo(peer))->isUpdating)
			{
				cout << "packet drop" << endl;
				continue;
			}

			/* Clean up the packet now that we're done using it. */
			int messageType = GetMessageTypeFromPacket(event.packet);

			WorldInfo* world = getPlyersWorld(peer);
			switch (messageType) {
			case 2:
			{
				//cout << GetTextPointerFromPacket(event.packet) << endl;
				string cch = GetTextPointerFromPacket(event.packet);
				string str = cch.substr(cch.find("text|") + 5, cch.length() - cch.find("text|") - 1);
				if (cch.find("action|wrench") == 0) {
					std::stringstream ss(cch);
					std::string to;
					int id = -1;
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if(infoDat.size() < 3) continue;
						if (infoDat[1] == "netid") {
							id = atoi(infoDat[2].c_str());
						}

					}
					if (id < 0) continue; //not found
 
					ENetPeer * currentPeer;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						if (isHere(peer, currentPeer)) {
							if ((playerInfo(currentPeer))->netID == id) {
								string name = (playerInfo(currentPeer))->displayName;
								packet::dialog(peer, "set_default_color|`o\nadd_label_with_icon|big|"+name+"|left|18|\nadd_spacer|small|\n\nadd_quick_exit|\nend_dialog|player_info||Close|");
							}

						}

					}
				}
				if (cch.find("action|setSkin") == 0) {
					if (!world) continue;
					std::stringstream ss(cch);
					std::string to;
					int id = -1;
					string color;
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat[0] == "color") color = infoDat[1];
						if (has_only_digits(color) == false) continue;
						id = atoi(color.c_str());
						if (color == "2190853119") {
							id = -2104114177;
						}
						else if (color == "2527912447") {
							id = -1767054849;
						}
						else if (color == "2864971775") {
							id = -1429995521;
						}
						else if (color == "3033464831") {
							id = -1261502465;
						}
						else if (color == "3370516479") {
							id = -924450817;
						}

					}
					(playerInfo(peer))->skinColor = id;
					sendClothes(peer);
				}
				if (cch.find("action|respawn") == 0)
				{
					int x = 3040;
					int y = 736;

					if (!world) continue;

					for (int i = 0; i < world->width*world->height; i++)
					{
						if (world->items[i].foreground == 6) {
							x = (i%world->width) * 32;
							y = (i / world->width) * 32;
						}
					}
					{
						PlayerMoving data;
						data.packetType = 0x0;
						data.characterState = 0x924; // animation
						data.x = x;
						data.y = y;
						data.punchX = -1;
						data.punchY = -1;
						data.XSpeed = 0;
						data.YSpeed = 0;
						data.netID = (playerInfo(peer))->netID;
						data.plantingTree = 0x0;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
					}
					
					{
						int x = 3040;
						int y = 736;

						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = GamePacketBuilder()
							.appendString("OnSetPos")
							.appendFloat(x, y)
							.build();
						memcpy(p2.data + 8, &((playerInfo(peer))->netID), 4);
						p2.send(peer);
					}
					{
						int x = 3040;
						int y = 736;

						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = GamePacketBuilder()
							.appendString("OnSetFreezeState")
							.appendIntx(0)
							.build();
						memcpy(p2.data + 8, &((playerInfo(peer))->netID), 4);
						p2.send(peer);
						//enet_host_flush(server);
					}
					cout << "Respawning... " << endl;
				}
				if (cch.find("action|growid") == 0)
				{
#ifndef REGISTRATION
					{
						GamePacket p = GamePacketBuilder()
							.appendString("OnConsoleMessage")
							.appendString("Registration is not supported yet!")
							.build()
							.send(peer);
						//enet_host_flush(server);
					}
#endif
#ifdef REGISTRATION
						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						packet::dialog(peer, "set_default_color|`o\n\nadd_label_with_icon|big|`wGet a GrowID``|left|206|\n\nadd_spacer|small|\nadd_textbox|A `wGrowID `wmeans `oyou can use a name and password to logon from any device.|\nadd_spacer|small|\nadd_textbox|This `wname `owill be reserved for you and `wshown to other players`o, so choose carefully!|\nadd_text_input|username|GrowID||30|\nadd_text_input|password|Password||100|\nadd_text_input|passwordverify|Password Verify||100|\nadd_textbox|Your `wemail address `owill only be used for account verification purposes and won't be spammed or shared. If you use a fake email, you'll never be able to recover or change your password.|\nadd_text_input|email|Email||100|\nadd_textbox|Your `wDiscord ID `owill be used for secondary verification if you lost access to your `wemail address`o! Please enter in such format: `wdiscordname#tag`o. Your `wDiscord Tag `ocan be found in your `wDiscord account settings`o.|\nadd_text_input|discord|Discord||100|\nend_dialog|register|Cancel|Get My GrowID!|\n");
#endif
				}
				if (cch.find("action|store") == 0)
				{
					packet::storeRequest(peer, "set_description_text|Welcome to the `2Growtopia Store``!  Tap the item you'd like more info on.`o  `wWant to get `5Supporter`` status? Any Gem purchase (or `57,000`` Gems earned with free `5Tapjoy`` offers) will make you one. You'll get new skin colors, the `5Recycle`` tool to convert unwanted items into Gems, and more bonuses!\nadd_button|iap_menu|Buy Gems|interface/large/store_buttons5.rttex||0|2|0|0||\nadd_button|subs_menu|Subscriptions|interface/large/store_buttons22.rttex||0|1|0|0||\nadd_button|token_menu|Growtoken Items|interface/large/store_buttons9.rttex||0|0|0|0||\nadd_button|pristine_forceps|`oAnomalizing Pristine Bonesaw``|interface/large/store_buttons20.rttex|Built to exacting specifications by GrowTech engineers to find and remove temporal anomalies from infected patients, and with even more power than Delicate versions! Note : The fragile anomaly - seeking circuitry in these devices is prone to failure and may break (though with less of a chance than a Delicate version)! Use with care!|0|3|3500|0||\nadd_button|itemomonth|`oItem Of The Month``|interface/large/store_buttons16.rttex|`2September 2018:`` `9Sorcerer's Tunic of Mystery!`` Capable of reflecting the true colors of the world around it, this rare tunic is made of captured starlight and aether. If you think knitting with thread is hard, just try doing it with moonbeams and magic! The result is worth it though, as these clothes won't just make you look amazing - you'll be able to channel their inherent power into blasts of cosmic energy!``|0|3|200000|0||\nadd_button|contact_lenses|`oContact Lens Pack``|interface/large/store_buttons22.rttex|Need a colorful new look? This pack includes 10 random Contact Lens colors (and may include Contact Lens Cleaning Solution, to return to your natural eye color)!|0|7|15000|0||\nadd_button|locks_menu|Locks And Stuff|interface/large/store_buttons3.rttex||0|4|0|0||\nadd_button|itempack_menu|Item Packs|interface/large/store_buttons3.rttex||0|3|0|0||\nadd_button|bigitems_menu|Awesome Items|interface/large/store_buttons4.rttex||0|6|0|0||\nadd_button|weather_menu|Weather Machines|interface/large/store_buttons5.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|4|0|0||\n");
				}
				if (cch.find("action|info") == 0)
				{
					std::stringstream ss(cch);
					std::string to;
					int id = -1;
					int count = -1;
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 3) {
							if (infoDat[1] == "itemID") id = atoi(infoDat[2].c_str());
							if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
						}
					}
					if (id == -1 || count == -1) continue;
					if (itemDefs.size() < id || id < 0) continue;
					packet::dialog(peer, "set_default_color|`o\n\nadd_label_with_icon|big|`w"+ itemDefs.at(id).name +"``|left|"+std::to_string(id)+"|\n\nadd_spacer|small|\nadd_textbox|"+ itemDefs.at(id).description +"|left|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|item_info|OK||");
				}
				if (cch.find("action|dialog_return") == 0)
				{
					std::stringstream ss(cch);
					std::string to;
					string btn = "";
					bool isRegisterDialog = false;
					string username = "";
					string password = "";
					string passwordverify = "";
					string email = "";
					string discord = "";
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 2) {
							if (infoDat[0] == "buttonClicked") btn = infoDat[1];
							if (infoDat[0] == "dialog_name" && infoDat[1] == "register")
							{
								isRegisterDialog = true;
							}
							if (isRegisterDialog) {
								if (infoDat[0] == "username") username = infoDat[1];
								if (infoDat[0] == "password") password = infoDat[1];
								if (infoDat[0] == "passwordverify") passwordverify = infoDat[1];
								if (infoDat[0] == "email") email = infoDat[1];
								if (infoDat[0] == "discord") discord = infoDat[1];
							}
						}
					}
					if (btn == "worldPublic") if ((playerInfo(peer))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
					if(btn == "worldPrivate") if ((playerInfo(peer))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = false;
#ifdef REGISTRATION
					if (isRegisterDialog) {

						int regState = PlayerDB::playerRegister(username, password, passwordverify, email, discord);
						if (regState == 1) {
							packet::consoleMessage(peer, "`rYour account has been created!``");
							GamePacketBuilder()
								.appendString("SetHasGrowID")
								.appendInt(1)
								.appendString(username)
								.appendString(password)
								.build()
								.send(peer);
							enet_peer_disconnect_later(peer, 0);
						}
						else if(regState==-1) {
							packet::consoleMessage(peer, "`rAccount creation has failed, because it already exists!``");
						}
						else if (regState == -2) {
							packet::consoleMessage(peer, "`rAccount creation has failed, because the name is too short!``");
						}
						else if (regState == -3) {
							packet::consoleMessage(peer, "`4Passwords mismatch!``");
						}
						else if (regState == -4) {
							packet::consoleMessage(peer, "`4Account creation has failed, because email address is invalid!``");
						}
						else if (regState == -5) {
							packet::consoleMessage(peer, "`4Account creation has failed, because Discord ID is invalid!``");
						}
					}
#endif
				}
				string dropText = "action|drop\n|itemID|";
				if (cch.find(dropText) == 0)
				{
					sendDrop(peer, -1, (playerInfo(peer))->x + (32 * ((playerInfo(peer))->isRotatedLeft?-1:1)), (playerInfo(peer))->y, atoi(cch.substr(dropText.length(), cch.length() - dropText.length() - 1).c_str()), 1, 0);
				}
				if (cch.find("text|") != std::string::npos){
					PlayerInfo* pData = (playerInfo(peer));
					if (str == "/mod")
					{
						(playerInfo(peer))->canWalkInBlocks = true;
						sendState(peer);
					}
					else if (str.substr(0, 7) == "/state ")
					{
						PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0x0; // animation
						data.x = 1000;
						data.y = 0;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = (playerInfo(peer))->netID;
						data.plantingTree = atoi(str.substr(7, cch.length() - 7 - 1).c_str());
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
					}
					else if (str == "/unequip")
					{
						(playerInfo(peer))->cloth_hair = 0;
						(playerInfo(peer))->cloth_shirt = 0;
						(playerInfo(peer))->cloth_pants = 0;
						(playerInfo(peer))->cloth_feet = 0;
						(playerInfo(peer))->cloth_face = 0;
						(playerInfo(peer))->cloth_hand = 0;
						(playerInfo(peer))->cloth_back = 0;
						(playerInfo(peer))->cloth_mask = 0;
						(playerInfo(peer))->cloth_necklace = 0;
						sendClothes(peer);
					}
					else if (str == "/wizard")
					{
						(playerInfo(peer))->cloth_hair = 0;
						(playerInfo(peer))->cloth_shirt = 0;
						(playerInfo(peer))->cloth_pants = 0;
						(playerInfo(peer))->cloth_feet = 0;
						(playerInfo(peer))->cloth_face = 1790;
						(playerInfo(peer))->cloth_hand = 0;
						(playerInfo(peer))->cloth_back = 0;
						(playerInfo(peer))->cloth_mask = 0;
						(playerInfo(peer))->cloth_necklace = 0;
						(playerInfo(peer))->skinColor = 2;
						sendClothes(peer);
						packet::consoleMessage(peer, "`^Legendary Wizard Set Mod has been Enabled! ");
					}
					else if (str.substr(0, 6) == "/find ")
					{
						ItemDefinition def;
						bool found = false;
						string itemname = str.substr(6, cch.length() - 6 - 1);
						for (int o = 0; o < itemDefs.size(); o++)
						{
							def = getItemDef(o);
							if (def.name == itemname)
							{
								packet::consoleMessage(peer, "`rItem ID of " + def.name + ": " + std::to_string(def.id));
								found = true;
							}
						}
						if (found == false)
						{
							packet::consoleMessage(peer, "`4Could not find the following item. Please use uppercase at the beggining, ( for example: Legendary Wings, not legendary wings ).");
						}
						found = false;
					}
					else if (str == "/mods") {
						string x;

						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (getAdminLevel((playerInfo(currentPeer))->rawName, (playerInfo(currentPeer))->tankIDPass) > 0) {
								x.append("`#@" + (playerInfo(currentPeer))->rawName + "``, ");
							}

						}
						x = x.substr(0, x.length() - 2);

						GamePacketBuilder()
							.appendString("OnConsoleMessage")
							.appendString("``Moderators online: " + x)
							.build()
							.send(peer);
					}
					else if (str.substr(0,10) == "/ducttape ") {
						if (getAdminLevel((playerInfo(peer))->rawName, (playerInfo(peer))->tankIDPass) > 0) {
							string name = str.substr(10, str.length());

							ENetPeer* currentPeer;

							bool found = false;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if ((playerInfo(currentPeer))->rawName == name) {
									found = true;
									if ((playerInfo(currentPeer))->taped) {
										(playerInfo(currentPeer))->taped = false;
										(playerInfo(currentPeer))->isDuctaped = false;
										
										packet::consoleMessage(peer, "`2You are no longer duct-taped!");
										sendState(currentPeer);
										{
											GamePacketBuilder()
												.appendString("OnConsoleMessage")
												.appendString("`2You have un duct-taped the player!")
												.build()
												.send(peer);
										}
									}
									else {
										(playerInfo(currentPeer))->taped = true;
										(playerInfo(currentPeer))->isDuctaped = true;
							
										GamePacketBuilder()
											.appendString("OnConsoleMessage")
											.appendString("`4You have been duct-taped!")
											.build()
											.send(currentPeer);
										sendState(currentPeer);
										{
											GamePacketBuilder()
												.appendString("OnConsoleMessage")
												.appendString("`2You have duct-taped the player!")
												.build()
												.send(peer);
										}
									}
								}
							}
							if (!found) {
								GamePacketBuilder()
									.appendString("OnConsoleMessage")
									.appendString("`4Player not found!")
									.build()
									.send(peer);
							}
						}
						else {
							GamePacketBuilder()
								.appendString("OnConsoleMessage")
								.appendString("`4You need to have a higher admin-level to do that!")
								.build()
								.send(peer);
						}
					}
					else if (str == "/help"){
						packet::consoleMessage(peer, "Supported commands are: /mods, /ducttape, /help, /mod, /unmod, /inventory, /item id, /team id, /color number, /who, /state number, /count, /sb message, /alt, /radio, /gem, /jsb, /find itemname, /unequip, /weather id, /nick nickname, /flag id, /wizard, /news, /loadnews");
					}
					else if (str == "/news"){
						packet::dialog(peer, newslist);
					}
					else if (str == "/loadnews"){
						if (!isSuperAdmin((playerInfo(peer))->rawName, (playerInfo(peer))->tankIDPass)) break;
						loadnews();//To load news instead of close server and run it again
					}
					else if (str.substr(0, 6) == "/nick ") {
						string nam1e = "```0" + str.substr(6, cch.length() - 6 - 1);
						(playerInfo(event.peer))->displayName = str.substr(6, cch.length() - 6 - 1);
						GamePacket p3 = GamePacketBuilder()
							.appendString("OnNameChanged")
							.appendString(nam1e)
							.build();
						memcpy(p3.data + 8, &((playerInfo(peer))->netID), 4);
					
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								p3.send(currentPeer);
							}
						}
					}
						else if (str.substr(0, 5) == "/gem ") //gem if u want flex with ur gems!
						{
						GamePacketBuilder()
							.appendString("OnSetBux")
							.appendInt(atoi(str.substr(5).c_str()))
							.build()
							.send(peer);
						continue;


						}
					else if (str.substr(0, 6) == "/flag ") {
						int lol = atoi(str.substr(6).c_str());
			
						GamePacket p2 = GamePacketBuilder()
							.appendString("OnGuildDataChanged")
							.appendIntx(1)
							.appendIntx(2)
							.appendIntx(lol)
							.appendIntx(3)
							.build();
						
						memcpy(p2.data + 8, &((playerInfo(peer))->netID), 4);
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer))
							{
								p2.send(currentPeer);
							}
						}
						}
					else if (str.substr(0, 9) == "/weather ") {
							if (world->name != "ADMIN") {
								if (world->owner != "") {
									if ((playerInfo(peer))->rawName == world->owner || isSuperAdmin((playerInfo(peer))->rawName, (playerInfo(peer))->tankIDPass))

									{
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												packet::consoleMessage(peer, "`oPlayer `2" + (playerInfo(peer))->displayName + "`o has just changed the world's weather!");

												GamePacketBuilder()
													.appendString("OnSetCurrentWeather")
													.appendInt(atoi(str.substr(9).c_str()))
													.build()
													.send(currentPeer);
												continue; /*CODE UPDATE /WEATHER FOR EVERYONE!*/
											}
										}
									}
								}
							}
						}
					else if (str == "/count"){
						int count = 0;
						ENetPeer * currentPeer;
						string name = "";
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							count++;
						}
						packet::consoleMessage(peer, "There are "+std::to_string(count)+" people online out of 1024 limit.");
					}
					else if (str.substr(0, 5) == "/asb "){
						if (!canSB((playerInfo(peer))->rawName, (playerInfo(peer))->tankIDPass)) continue;
						cout << "ASB from " << (playerInfo(peer))->rawName <<  " in world " << (playerInfo(peer))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						GamePacket p = GamePacketBuilder()
							.appendString("OnAddNotification")
							.appendString("interface/atomic_button.rttex")
							.appendString(str.substr(4, cch.length() - 4 - 1).c_str())
							.appendString("audio/hub_open.wav")
							.appendInt(0)
							.build();
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							p.send(currentPeer);
						}
					}
					else if (str == "/invis") {
						packet::consoleMessage(peer, "`6" + str);
						if (!pData->isGhost) {

							packet::consoleMessage(peer, "`oYour atoms are suddenly aware of quantum tunneling. (Ghost in the shell mod added)");

							GamePacket p2 = GamePacketBuilder()
								.appendString("OnSetPos")
								.appendFloat(pData->x, pData->y)
								.build();
							memcpy(p2.data + 8, &((playerInfo(peer))->netID), 4);
							p2.send(peer);

							sendState(peer);
							sendClothes(peer);
							pData->isGhost = true;
						}
						else {
							packet::consoleMessage(peer, "`oYour body stops shimmering and returns to normal. (Ghost in the shell mod removed)");

							GamePacket p2 = GamePacketBuilder()
								.appendString("OnSetPos")
								.appendFloat(pData->x1, pData->y1)
								.build();
							memcpy(p2.data + 8, &((playerInfo(peer))->netID), 4);
							p2.send(peer);

							(playerInfo(peer))->isInvisible = false;
							sendState(peer);
							sendClothes(peer);
							pData->isGhost = false;
						}
					}
					
					else if (str.substr(0, 4) == "/sb ") {
						using namespace std::chrono;
						if ((playerInfo(peer))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							(playerInfo(peer))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							packet::consoleMessage(peer, "Wait a minute before using the SB command again!");
							continue;
						}

						string name = (playerInfo(peer))->displayName;
						GamePacket p = GamePacketBuilder()
							.appendString("OnConsoleMessage")
							.appendString("CP:0_PL:4_OID:_CT:[SB]_ `w** `5Super-Broadcast`` from `$`2" + name + "```` (in `$" + (playerInfo(peer))->currentWorld + "``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1))
							.build();
						string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer * currentPeer;
						
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!(playerInfo(currentPeer))->radio)
								continue;
							p.send(currentPeer);
							
							
							ENetPacket * packet2 = enet_packet_create(data,
								5+text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);
							
							//enet_host_flush(server);
						}
						delete[] data;
					}
					else if (str.substr(0, 5) == "/jsb ") {
						using namespace std::chrono;
						if ((playerInfo(peer))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							(playerInfo(peer))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							packet::consoleMessage(peer, "Wait a minute before using the JSB command again!");
							continue;
						}

						string name = (playerInfo(peer))->displayName;
						GamePacket p = GamePacketBuilder()
							.appendString("OnConsoleMessage")
							.appendString("`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `4JAMMED``) ** :`` `# " + str.substr(5, cch.length() - 5 - 1))
							.build();
						string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer * currentPeer;
						
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!(playerInfo(currentPeer))->radio)
								continue;
							
							p.send(currentPeer);
							ENetPacket * packet2 = enet_packet_create(data,
								5+text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);
							
							//enet_host_flush(server);
						}
						delete[] data;
					}
					
					
					else if (str.substr(0, 6) == "/radio") {
						GamePacketBuilder& builder = GamePacketBuilder()
							.appendString("OnConsoleMessage");
						
						if ((playerInfo(peer))->radio) {
							builder
								.appendString("You won't see broadcasts anymore.")
								.build();
							(playerInfo(peer))->radio = false;
						} else {
							builder
								.appendString("You will now see broadcasts again.")
								.build();
							(playerInfo(peer))->radio = true;
						}
						GamePacket p = builder.build();
						p.send(peer);
					}
					else if (str.substr(0, 6) == "/reset"){
						if (!isSuperAdmin((playerInfo(peer))->rawName, (playerInfo(peer))->tankIDPass)) break;
						cout << "Restart from " << (playerInfo(peer))->displayName << endl;
						GamePacket p = GamePacketBuilder()
							.appendString("OnAddNotification")
							.appendString("interface/science_button.rttex")
							.appendString("Restarting soon!")
							.appendString("audio/mp3/suspended.mp3")
							.appendInt(0)
							.build();
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							p.send(currentPeer);;
						}
					}

					else if (str == "/unmod")
					{
						(playerInfo(peer))->canWalkInBlocks = false;
						sendState(peer);
					}
					else if (str == "/alt") {
					GamePacketBuilder()
						.appendString("OnSetBetaMode")
						.appendInt(1)
						.build()
						.send(peer);
						
						//enet_host_flush(server);
					}
					else
					if (str == "/inventory")
					{
						sendInventory(peer, (playerInfo(peer))->inventory);
					} else
					if (str.substr(0,6) == "/item ")
					{
						PlayerInventory inventory;
						InventoryItem item;
						item.itemID = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						item.itemCount = 200;
						inventory.items.push_back(item);
						item.itemCount = 1;
						item.itemID = 18;
						inventory.items.push_back(item);
						item.itemID = 32;
						inventory.items.push_back(item);
						sendInventory(peer, inventory);
					} else
					if (str.substr(0, 6) == "/team ")
					{
						int val = 0;
						val = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						PlayerMoving data;
						//data.packetType = 0x14;
						data.packetType = 0x1B;
						//data.characterState = 0x924; // animation
						data.characterState = 0x0; // animation
						data.x = 0;
						data.y = 0;
						data.punchX = val;
						data.punchY = 0;
						data.XSpeed = 0;
						data.YSpeed = 0;
						data.netID = (playerInfo(peer))->netID;
						data.plantingTree = 0;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

					} else 
					if (str.substr(0, 7) == "/color ")
					{
						(playerInfo(peer))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						sendClothes(peer);
					}
					if (str.substr(0, 4) == "/who")
					{
						sendWho(peer);

					}
					if (str.length() && str[0] == '/')
					{
						sendAction(peer, (playerInfo(peer))->netID, str);
					} else if (str.length()>0)
					{
						if ((playerInfo(peer))->taped == false) {
							sendChatMessage(peer, (playerInfo(peer))->netID, str);
						}
						else {
							// Is duct-taped
							sendChatMessage(peer, (playerInfo(peer))->netID, randomDuctTapeMessage(str.length()));
						}
					}
					
			}
				if (!(playerInfo(event.peer))->isIn)
				{
					if (itemdathash == 0) {
						enet_peer_disconnect_later(peer, 0);
					}
					GamePacketBuilder()
						.appendString("OnSuperMainStartAcceptLogonHrdxs47254722215a")
						.appendInt(itemdathash)
						.appendString("ubistatic-a.akamaihd.net")
						.appendString(configCDN)
						.appendString("cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster")
						.appendString("proto=84|choosemusic=audio/mp3/about_theme.mp3|active_holiday=0|server_tick=226933875|clash_active=0|drop_lavacheck_faster=1|isPayingUser=0|")
						.build()
						.send(peer);

					
					std::stringstream ss(GetTextPointerFromPacket(event.packet));
					std::string to;
					while (std::getline(ss, to, '\n')){
						string id = to.substr(0, to.find("|"));
						string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
						if (id == "tankIDName")
						{
							(playerInfo(event.peer))->tankIDName = act;
							(playerInfo(event.peer))->haveGrowId = true;
						}
						else if(id == "tankIDPass")
						{
							(playerInfo(event.peer))->tankIDPass = act;
						}
						else if(id == "requestedName")
						{
							(playerInfo(event.peer))->requestedName = act;
						}
						else if (id == "country")
						{
							(playerInfo(event.peer))->country = act;
						}
					}
					if (!(playerInfo(event.peer))->haveGrowId)
					{
						(playerInfo(event.peer))->hasLogon = true;
						(playerInfo(event.peer))->rawName = "";
						(playerInfo(event.peer))->displayName = "Fake " + PlayerDB::fixColors((playerInfo(event.peer))->requestedName.substr(0, (playerInfo(event.peer))->requestedName.length()>15?15:(playerInfo(event.peer))->requestedName.length()));
					}
					else {
						(playerInfo(event.peer))->rawName = PlayerDB::getProperName((playerInfo(event.peer))->tankIDName);
#ifdef REGISTRATION
						int logStatus = PlayerDB::playerLogin(peer, (playerInfo(event.peer))->rawName, (playerInfo(event.peer))->tankIDPass);
						if (logStatus == 1) {
							packet::consoleMessage(peer, "`rYou have successfully logged into your account!``");
							(playerInfo(event.peer))->displayName = (playerInfo(event.peer))->tankIDName;
						}
						else {
							packet::consoleMessage(peer, "`rWrong username or password!``");
							enet_peer_disconnect_later(peer, 0);
						}
#else
						
						(playerInfo(event.peer))->displayName = PlayerDB::fixColors((playerInfo(event.peer))->tankIDName.substr(0, (playerInfo(event.peer))->tankIDName.length()>18 ? 18 : (playerInfo(event.peer))->tankIDName.length()));
						if ((playerInfo(event.peer))->displayName.length() < 3) (playerInfo(event.peer))->displayName = "Person that doesn't know how the name looks!";
#endif
					}
					for (char c : (playerInfo(event.peer))->displayName) if (c < 0x20 || c>0x7A) (playerInfo(event.peer))->displayName = "Bad characters in name, remove them!";
					
					if ((playerInfo(event.peer))->country.length() > 4)
					{
						(playerInfo(event.peer))->country = "us";
					}
					if (getAdminLevel((playerInfo(event.peer))->rawName, (playerInfo(event.peer))->tankIDPass) > 0)
					{
						(playerInfo(event.peer))->country = "../cash_icon_overlay";
					}

					GamePacketBuilder()
						.appendString("SetHasGrowID")
						.appendInt(playerInfo(event.peer)->haveGrowId)
						.appendString(playerInfo(peer)->tankIDName)
						.appendString(playerInfo(peer)->tankIDPass)
						.build()
						.send(peer);

					
				}
				string pStr = GetTextPointerFromPacket(event.packet);
				if(pStr.substr(0, 17) == "action|enter_game" && !(playerInfo(event.peer))->isIn)
				{
					cout << "And we are in!" << endl;
					ENetPeer* currentPeer;
					(playerInfo(event.peer))->isIn = true;
					sendWorldOffers(peer);
					
					// growmoji
					GamePacketBuilder()
						.appendString("OnEmoticonDataChanged")
						.appendInt(201560520)
						.appendString("(wl)|Ä|1&(yes)|Ä‚|1&(no)|Äƒ|1&(love)|Ä„|1&(oops)|Ä…|1&(shy)|Ä†|1&(wink)|Ä‡|1&(tongue)|Äˆ|1&(agree)|Ä‰|1&(sleep)|ÄŠ|1&(punch)|Ä‹|1&(music)|ÄŒ|1&(build)|Ä|1&(megaphone)|ÄŽ|1&(sigh)|Ä|1&(mad)|Ä|1&(wow)|Ä‘|1&(dance)|Ä’|1&(see-no-evil)|Ä“|1&(bheart)|Ä”|1&(heart)|Ä•|1&(grow)|Ä–|1&(gems)|Ä—|1&(kiss)|Ä˜|1&(gtoken)|Ä™|1&(lol)|Äš|1&(smile)|Ä€|1&(cool)|Äœ|1&(cry)|Ä|1&(vend)|Äž|1&(bunny)|Ä›|1&(cactus)|ÄŸ|1&(pine)|Ä¤|1&(peace)|Ä£|1&(terror)|Ä¡|1&(troll)|Ä¢|1&(evil)|Ä¢|1&(fireworks)|Ä¦|1&(football)|Ä¥|1&(alien)|Ä§|1&(party)|Ä¨|1&(pizza)|Ä©|1&(clap)|Äª|1&(song)|Ä«|1&(ghost)|Ä¬|1&(nuke)|Ä­|1&(halo)|Ä®|1&(turkey)|Ä¯|1&(gift)|Ä°|1&(cake)|Ä±|1&(heartarrow)|Ä²|1&(lucky)|Ä³|1&(shamrock)|Ä´|1&(grin)|Äµ|1&(ill)|Ä¶|1&")
						.build()
						.send(peer);
					
					
					packet::consoleMessage(peer, "Server made by Growtopia Noobs, some fixes by iProgramInCpp and items from Nenkai.");
					PlayerInventory inventory;
					for (int i = 0; i < 200; i++)
					{
						InventoryItem it;
						it.itemID = (i * 2) + 2;
						it.itemCount = 200;
						inventory.items.push_back(it);
					}
					(playerInfo(event.peer))->inventory = inventory;

					{
						packet::dialog(peer, newslist);
					}
				}
				if (strcmp(GetTextPointerFromPacket(event.packet), "action|refresh_item_data\n") == 0)
				{
					if (itemsDat != NULL) {
						ENetPacket * packet = enet_packet_create(itemsDat,
							itemsDatSize + 60,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						(playerInfo(peer))->isUpdating = true;

					}
				}
				break;
			}
			default:
				cout << "Unknown packet type " << messageType << endl;
				break;
			case 3:
			{
				std::stringstream ss(GetTextPointerFromPacket(event.packet));
				std::string to;
				bool isJoinReq = false;
								
				while (std::getline(ss, to, '\n')) {
					string id = to.substr(0, to.find("|"));
					string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
					if (id == "name" && isJoinReq)
					{
						cout << "Entering some world..." << endl;
						if (!(playerInfo(peer))->hasLogon) break;
						try {
							if (act.length() > 30) {
								packet::consoleMessage(peer, "`4Sorry, but world names with more than 30 characters are not allowed!");
								(playerInfo(peer))->currentWorld = "EXIT";
								GamePacketBuilder()
									.appendString("OnFailedToEnterWorld")
									.appendIntx(1)
									.build()
									.send(peer);
							} else {
								WorldInfo info = worldDB.get(act);
								sendWorld(peer, &info);

								int x = 3040;
								int y = 736;

								for (int j = 0; j < info.width*info.height; j++)
								{
									if (info.items[j].foreground == 6) {
										x = (j%info.width) * 32;
										y = (j / info.width) * 32;
									}
								}
								packet::onSpawn(peer, "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + (playerInfo(event.peer))->displayName + "``\ncountry|" + (playerInfo(event.peer))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n");
								(playerInfo(event.peer))->netID = cId;
								onPeerConnect(peer);
								cId++;

								sendInventory(peer, (playerInfo(event.peer))->inventory);

                                                                if ((playerInfo(peer))->taped) {
                                                                (playerInfo(peer))->isDuctaped = true;
                                                                sendState(peer);
                                                                }
							}
						}
						catch (int e) {
							if (e == 1) {
								(playerInfo(peer))->currentWorld = "EXIT";
								GamePacketBuilder()
									.appendString("OnFailedToEnterWorld")
									.appendIntx(1)
									.build()
									.send(peer);
								packet::consoleMessage(peer, "You have exited the world.");
							}
							else if (e == 2) {
								(playerInfo(peer))->currentWorld = "EXIT";
								GamePacketBuilder()
									.appendString("OnFailedToEnterWorld")
									.appendIntx(1)
									.build()
									.send(peer);
								packet::consoleMessage(peer, "You have entered bad characters in the world name!");
							}
							else if (e == 3) {
								(playerInfo(peer))->currentWorld = "EXIT";
								GamePacketBuilder()
									.appendString("OnFailedToEnterWorld")
									.appendIntx(1)
									.build()
									.send(peer);
								packet::consoleMessage(peer, "Exit from what? Click back if you're done playing.");
							}
							else {
								(playerInfo(peer))->currentWorld = "EXIT";
								GamePacketBuilder()
									.appendString("OnFailedToEnterWorld")
									.appendIntx(1)
									.build()
									.send(peer);
								packet::consoleMessage(peer, "I know this menu is magical and all, but it has its limitations! You can't visit this world!");
							}
						}
					}
						if (id == "action")
						{

							if (act == "join_request")
							{
								isJoinReq = true;
							}
							if (act == "quit_to_exit")
							{
								sendPlayerLeave(peer, playerInfo(event.peer));
								(playerInfo(peer))->currentWorld = "EXIT";
								sendWorldOffers(peer);

							}
							if (act == "quit")
							{
								enet_peer_disconnect_later(peer, 0);
							}
						}
					}
					break;
			}
			case 4:
			{
				{
					BYTE* tankUpdatePacket = GetStructPointerFromTankPacket(event.packet); 
					
					if (tankUpdatePacket)
					{
						PlayerMoving* pMov = unpackPlayerMoving(tankUpdatePacket);
						if ((playerInfo(event.peer))->isGhost) {
							(playerInfo(event.peer))->isInvisible = true;
							(playerInfo(event.peer))->x1 = pMov->x;
							(playerInfo(event.peer))->y1 = pMov->y;
							pMov->x = -1000000;
							pMov->y = -1000000;
						}
						
						switch (pMov->packetType)
						{
						case 0:
							(playerInfo(event.peer))->x = pMov->x;
							(playerInfo(event.peer))->y = pMov->y;
							(playerInfo(event.peer))->isRotatedLeft = pMov->characterState & 0x10;
							sendPData(peer, pMov);
							if (!(playerInfo(peer))->joinClothesUpdated)
							{
								(playerInfo(peer))->joinClothesUpdated = true;
								updateAllClothes(peer);
							}
							break;

						default:
							break;
						}
						PlayerMoving *data2 = unpackPlayerMoving(tankUpdatePacket);
						if (data2->packetType == 11)
						{
							// lets take item
						}
						if (data2->packetType == 7)
						{
							if(data2->punchX < world->width && data2->punchY < world->height)
							if (getItemDef(world->items[data2->punchX + (data2->punchY * world->width)].foreground).blockType == BlockTypes::MAIN_DOOR) {
									sendPlayerLeave(peer, playerInfo(event.peer));
									(playerInfo(peer))->currentWorld = "EXIT";
									sendWorldOffers(peer);

								}
						}
						if (data2->packetType == 10)
						{
							//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << ";" << pMov->punchY << ";" << pMov->characterState << endl;
							ItemDefinition def;
							try {
								def = getItemDef(pMov->plantingTree);
							}
							catch (int e) {
								goto END_CLOTHSETTER_FORCE;
							}
							
							switch (def.clothType) {
							case 0:
								if ((playerInfo(event.peer))->cloth0 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth0 = 0;
									break;
								}
								(playerInfo(event.peer))->cloth0 = pMov->plantingTree;
								break;
							case 1:
								if ((playerInfo(event.peer))->cloth1 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth1 = 0;
									break;
								}
								(playerInfo(event.peer))->cloth1 = pMov->plantingTree;
								break;
							case 2:
								if ((playerInfo(event.peer))->cloth2 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth2 = 0;
									break;
								}
								(playerInfo(event.peer))->cloth2 = pMov->plantingTree;
								break;
							case 3:
								if ((playerInfo(event.peer))->cloth3 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth3 = 0;
									break;
								}
								(playerInfo(event.peer))->cloth3 = pMov->plantingTree;
								break;
							case 4:
								if ((playerInfo(event.peer))->cloth4 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth4 = 0;
									break;
								}
								(playerInfo(event.peer))->cloth4 = pMov->plantingTree;
								break;
							case 5:
								if ((playerInfo(event.peer))->cloth5 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth5 = 0;
									break;
								}
								(playerInfo(event.peer))->cloth5 = pMov->plantingTree;
								break;
							case 6:
								if ((playerInfo(event.peer))->cloth6 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth6 = 0;
									(playerInfo(event.peer))->canDoubleJump = false;
									sendState(peer);
									break;
								}
								{
									(playerInfo(event.peer))->cloth6 = pMov->plantingTree;
									int item = pMov->plantingTree;
									if (item == 156 || item == 362 || item == 678 || item == 736 || item == 818 || item == 1206 || item == 1460 || item == 1550 || item == 1574 || item == 1668 || item == 1672 || item == 1674 || item == 1784 || item == 1824 || item == 1936 || item == 1938 || item == 1970 || item == 2254 || item == 2256 || item == 2258 || item == 2260 || item == 2262 || item == 2264 || item == 2390 || item == 2392 || item == 3120 || item == 3308 || item == 3512 || item == 4534 || item == 4986 || item == 5754 || item == 6144 || item == 6334 || item == 6694 || item == 6818 || item == 6842 || item == 1934 || item == 3134 || item == 6004 || item == 1780 || item == 2158 || item == 2160 || item == 2162 || item == 2164 || item == 2166 || item == 2168 || item == 2438 || item == 2538 || item == 2778 || item == 3858 || item == 350 || item == 998 || item == 1738 || item == 2642 || item == 2982 || item == 3104 || item == 3144 || item == 5738 || item == 3112 || item == 2722 || item == 3114 || item == 4970 || item == 4972 || item == 5020 || item == 6284 || item == 4184 || item == 4628 || item == 5322 || item == 4112 || item == 4114 || item == 3442) {
										(playerInfo(event.peer))->canDoubleJump = true;
									}
									else {
										(playerInfo(event.peer))->canDoubleJump = false;
									}
									// ^^^^ wings
									sendState(peer);
								}
								break;
							case 7:
								if ((playerInfo(event.peer))->cloth7 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth7 = 0;
									break;
								}
								(playerInfo(event.peer))->cloth7 = pMov->plantingTree;
								break;
							case 8:
								if ((playerInfo(event.peer))->cloth8 == pMov->plantingTree)
								{
									(playerInfo(event.peer))->cloth8 = 0;
									break;
								}
								(playerInfo(event.peer))->cloth8 = pMov->plantingTree;
								break;
							default:
								cout << "Invalid item activated: " << pMov->plantingTree << " by " << (playerInfo(event.peer))->displayName << endl;
								break;
							}
							sendClothes(peer);
							// activate item
						END_CLOTHSETTER_FORCE:;
						}
						if (data2->packetType == 18)
						{
							sendPData(peer, pMov);
							// add talk buble
						}
						if (data2->punchX != -1 && data2->punchY != -1) {
							if (data2->packetType == 3)
							{
								sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, (playerInfo(event.peer))->netID, peer);
							}
							else {

							}
							
						}
						delete data2;
						delete pMov;
					}

					else {
						cout << "Got bad tank packet";
					}
				}
			}
			break;
			case 5:
				break;
			case 6:
				//cout << GetTextPointerFromPacket(event.packet) << endl;
				break;
			}
			enet_packet_destroy(event.packet);
			break;
		}
		case ENET_EVENT_TYPE_DISCONNECT:
			printf("Peer disconnected.\n");
			/* Reset the peer's client information. */
			sendPlayerLeave(peer, playerInfo(event.peer));
			(playerInfo(event.peer))->inventory.items.clear();
			delete (PlayerInfo*)event.peer->data;
			event.peer->data = NULL;
		}
	}
	cout << "Program ended??? Huh?" << endl;
	return 0;
}
