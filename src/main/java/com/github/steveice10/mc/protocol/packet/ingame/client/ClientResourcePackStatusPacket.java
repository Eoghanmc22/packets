package com.github.steveice10.mc.protocol.packet.ingame.client;

import com.github.steveice10.mc.protocol.data.MagicValues;
import com.github.steveice10.mc.protocol.data.game.ResourcePackStatus;
import com.github.steveice10.packetlib.io.NetInput;
import com.github.steveice10.packetlib.io.NetOutput;
import com.github.steveice10.packetlib.packet.Packet;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;

import java.io.IOException;

@Data
@Setter(AccessLevel.NONE)
@NoArgsConstructor()
@AllArgsConstructor
public class ClientResourcePackStatusPacket implements Packet {
    private @NonNull ResourcePackStatus status;

    @Override
    public void read(NetInput in) throws IOException {
        this.status = MagicValues.key(ResourcePackStatus.class, in.readVarInt());
    }

    @Override
    public void write(NetOutput out) throws IOException {
        out.writeVarInt(MagicValues.value(Integer.class, this.status));
    }

    @Override
    public boolean isPriority() {
        return false;
    }
}
