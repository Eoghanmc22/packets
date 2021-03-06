package com.github.steveice10.mc.protocol.packet.ingame.server;

import com.github.steveice10.packetlib.io.NetInput;
import com.github.steveice10.packetlib.io.NetOutput;
import com.github.steveice10.packetlib.packet.Packet;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.IOException;

@Data
@Setter(AccessLevel.NONE)
@NoArgsConstructor()
@AllArgsConstructor
public class ServerKeepAlivePacket implements Packet {
    private long pingId;

    @Override
    public void read(NetInput in) throws IOException {
        this.pingId = in.readLong();
    }

    @Override
    public void write(NetOutput out) throws IOException {
        out.writeLong(this.pingId);
    }

    @Override
    public boolean isPriority() {
        return false;
    }
}
